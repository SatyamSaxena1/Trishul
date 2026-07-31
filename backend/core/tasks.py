import logging
from uuid import UUID

from celery import shared_task
from django.db import connection, transaction
from django.utils import timezone

from .ai_gateway import invoke
from .metrics import DETERMINISTIC_ANALYSIS_FAILURES, OPTIONAL_AI_FAILURES
from .models import (
    AIAnalysisRun,
    AuditEvent,
    Finding,
    FindingEvidence,
    Job,
    ModelConfiguration,
    PromptVersion,
    RiskAcceptance,
    Scan,
    Tenant,
)
from .runner import analyze
from .tenancy import tenant_context

logger = logging.getLogger(__name__)


def _database_tenant(tenant_id):
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])


@shared_task(name="core.tasks.execute_scan", acks_late=True)
def execute_scan(tenant_id, scan_id):
    tenant_id = UUID(str(tenant_id))
    with transaction.atomic(), tenant_context(tenant_id):
        _database_tenant(tenant_id)
        scan = Scan.objects.select_for_update().select_related("repository_version").get(pk=scan_id)
        if scan.state != Scan.State.QUEUED:
            return
        scan.state = Scan.State.RUNNING
        scan.version += 1
        scan.save(update_fields=["state", "version", "updated_at"])
    try:
        result = analyze(repository_version=scan.repository_version, scan_id=scan.id)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            scan = Scan.objects.select_for_update().get(pk=scan_id)
            for item in result["findings"]:
                finding = Finding.all_objects.create(
                    tenant_id=tenant_id,
                    scan=scan,
                    rule_id=item["rule_id"],
                    rule_version=item["rule_version"],
                    language="python",
                    title=item["title"],
                    description=item["description"],
                    cwe=item["cwe"],
                    asvs=item["asvs"],
                    severity=item["severity"],
                    confidence=item["confidence"],
                    status=item["status"],
                    remediation=item["remediation"],
                    fingerprint=item["fingerprint"],
                )
                FindingEvidence.all_objects.create(
                    tenant_id=tenant_id,
                    finding=finding,
                    file_path=item["file_path"],
                    start_line=item["start_line"],
                    end_line=item["end_line"],
                    snippet_hash=item["snippet_hash"],
                )
            scan.coverage = result["coverage"]
            scan.state = Scan.State.COMPLETED
            scan.version += 1
            scan.save(update_fields=["coverage", "state", "version", "updated_at"])
            Job.objects.filter(payload__scan_id=str(scan_id)).update(state=Job.State.COMPLETED, error_code="")
            AuditEvent.append(
                tenant=scan.tenant,
                actor_type="system",
                actor_id="analysis-controller",
                action="scan.completed",
                resource_type="core.scan",
                resource_id=scan.id,
                details={
                    "findings": len(result["findings"]),
                    "pack": result["pack"],
                    "pack_version": result["pack_version"],
                },
            )
        # Completion is durable before best-effort enrichment is even queued.
        try:
            enrich_scan.apply_async(args=[str(tenant_id), str(scan_id)], queue="ai")
        except Exception:
            OPTIONAL_AI_FAILURES.labels(reason="enqueue").inc()
            logger.exception("Optional AI enrichment could not be queued for %s", scan_id)
    except Exception as exc:
        DETERMINISTIC_ANALYSIS_FAILURES.inc()
        logger.exception("Scan failed for %s", scan_id)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            Scan.objects.filter(pk=scan_id).update(state=Scan.State.FAILED, version=scan.version + 1)
            Job.objects.filter(payload__scan_id=str(scan_id)).update(
                state=Job.State.FAILED, error_code=type(exc).__name__[:80]
            )
        raise


ENRICHMENT_SCHEMA = {
    "type": "object",
    "required": ["findings"],
    "additionalProperties": False,
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["finding_id", "summary", "suggested_remediation"],
                "additionalProperties": False,
                "properties": {
                    "finding_id": {"type": "string"},
                    "summary": {"type": "string", "maxLength": 4000},
                    "suggested_remediation": {"type": "string", "maxLength": 4000},
                },
            },
        }
    },
}


@shared_task(name="core.tasks.enrich_scan", acks_late=True)
def enrich_scan(tenant_id, scan_id):
    """Best-effort advisory enrichment; deterministic fields are never written."""
    tenant_id = UUID(str(tenant_id))
    try:
        with tenant_context(tenant_id):
            configuration = ModelConfiguration.objects.filter(is_active=True).order_by("created_at").first()
            prompt = (
                PromptVersion.objects.filter(workflow="scan_enrichment", approved_at__isnull=False)
                .order_by("-approved_at")
                .first()
            )
            if not configuration or not prompt:
                return {"state": "disabled"}
            findings = list(
                Finding.objects.filter(scan_id=scan_id).values(
                    "id", "rule_id", "title", "description", "severity", "confidence", "status", "remediation"
                )
            )
            output, metadata = invoke(
                configuration=configuration,
                workflow="scan_enrichment",
                messages=[{"role": "user", "content": str(findings)}],
                response_schema=ENRICHMENT_SCHEMA,
            )
            by_id = {str(finding.id): finding for finding in Finding.objects.filter(scan_id=scan_id)}
            advisories = output["findings"]
            if any(item["finding_id"] not in by_id for item in advisories):
                raise ValueError("AI output references a finding outside this scan.")
            with transaction.atomic():
                for item in advisories:
                    finding = by_id[item["finding_id"]]
                    finding.ai_advisory = {
                        "label": "AI-generated advisory",
                        "summary": item["summary"],
                        "suggested_remediation": item["suggested_remediation"],
                    }
                    finding.save(update_fields=["ai_advisory", "updated_at"])
                AIAnalysisRun.all_objects.create(
                    tenant_id=tenant_id,
                    model_configuration=configuration,
                    prompt_version=prompt,
                    workflow="scan_enrichment",
                    state="accepted",
                    request_hash=metadata["request_hash"],
                    response_hash=metadata["response_hash"],
                    input_tokens=metadata["input_tokens"],
                    output_tokens=metadata["output_tokens"],
                    policy_decisions=["advisory_only", "structured_output:valid"],
                )
            return {"state": "accepted"}
    except Exception as exc:
        OPTIONAL_AI_FAILURES.labels(reason=type(exc).__name__[:80]).inc()
        logger.exception("Optional AI enrichment failed for %s", scan_id)
        return {"state": "failed", "error": type(exc).__name__}


@shared_task(name="core.tasks.reconcile_jobs")
def reconcile_jobs():
    now = timezone.now()
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            stale = Job.objects.filter(state=Job.State.RUNNING, lease_expires_at__lt=now)
            for job in stale.select_for_update():
                job.state = Job.State.QUEUED if job.attempts < 3 else Job.State.FAILED
                job.error_code = "lease_expired"
                job.version += 1
                job.save(update_fields=["state", "error_code", "version", "updated_at"])


@shared_task(name="core.tasks.expire_acceptances")
def expire_acceptances():
    now = timezone.now()
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            RiskAcceptance.objects.filter(status="approved", expires_at__lte=now).update(status="expired")
