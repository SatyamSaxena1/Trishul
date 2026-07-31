import logging

from celery import shared_task
from django.db import connection, transaction
from django.utils import timezone

from .models import AuditEvent, Finding, FindingEvidence, Job, RiskAcceptance, Scan, Tenant
from .runner import analyze
from .tenancy import tenant_context

logger = logging.getLogger(__name__)


def _database_tenant(tenant_id):
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])


def publish_scan(job_id):
    """Publish a durable dispatch intent, leaving it pending for reconciliation on failure."""
    job = Job.all_objects.get(pk=job_id)
    try:
        execute_scan.apply_async(
            args=[str(job.tenant_id), job.payload["scan_id"]],
            queue="analysis",
        )
    except Exception:
        logger.exception("Could not publish scan job %s; dispatch remains pending", job_id)
        Job.all_objects.filter(pk=job_id).update(error_code="queue_publish_failed")
        return False
    Job.all_objects.filter(pk=job_id).update(dispatch_pending=False, error_code="")
    return True


@shared_task(name="core.tasks.execute_scan", acks_late=True)
def execute_scan(tenant_id, scan_id):
    with transaction.atomic(), tenant_context(tenant_id):
        _database_tenant(tenant_id)
        scan = Scan.objects.select_for_update().select_related("repository_version").get(pk=scan_id)
        if scan.state not in {Scan.State.QUEUED, Scan.State.RUNNING}:
            return
        if scan.state == Scan.State.QUEUED:
            scan.state = Scan.State.RUNNING
            scan.version += 1
            scan.save(update_fields=["state", "version", "updated_at"])
            Job.objects.filter(payload__scan_id=str(scan_id)).update(state=Job.State.RUNNING)
    try:
        result = analyze(repository_version=scan.repository_version, scan_id=scan.id)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            scan = Scan.objects.select_for_update().get(pk=scan_id)
            for item in result["findings"]:
                finding, _ = Finding.all_objects.update_or_create(
                    tenant_id=tenant_id,
                    scan=scan,
                    fingerprint=item["fingerprint"],
                    defaults={
                        "rule_id": item["rule_id"],
                        "rule_version": item["rule_version"],
                        "language": "python",
                        "title": item["title"],
                        "description": item["description"],
                        "cwe": item["cwe"],
                        "asvs": item["asvs"],
                        "severity": item["severity"],
                        "confidence": item["confidence"],
                        "status": item["status"],
                        "remediation": item["remediation"],
                    },
                )
                FindingEvidence.all_objects.update_or_create(
                    tenant_id=tenant_id,
                    finding=finding,
                    file_path=item["file_path"],
                    start_line=item["start_line"],
                    end_line=item["end_line"],
                    defaults={
                        "snippet_hash": item["snippet_hash"],
                    },
                )
            scan.coverage = result["coverage"]
            scan.state = Scan.State.COMPLETED
            scan.version += 1
            scan.save(update_fields=["coverage", "state", "version", "updated_at"])
            Job.objects.filter(payload__scan_id=str(scan_id)).update(state=Job.State.COMPLETED)
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
    except Exception as exc:
        logger.exception("Scan failed for %s", scan_id)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            Scan.objects.filter(pk=scan_id).update(state=Scan.State.FAILED, version=scan.version + 1)
            Job.objects.filter(payload__scan_id=str(scan_id)).update(
                state=Job.State.FAILED, error_code=type(exc).__name__[:80]
            )
        raise


@shared_task(name="core.tasks.reconcile_jobs")
def reconcile_jobs():
    now = timezone.now()
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        pending_ids = Job.all_objects.filter(
            tenant_id=tenant_id, dispatch_pending=True, state=Job.State.QUEUED
        ).values_list("id", flat=True)
        for job_id in pending_ids:
            publish_scan(str(job_id))
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
