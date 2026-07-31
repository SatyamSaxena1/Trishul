import logging
import os
import uuid
from datetime import timedelta

from celery import shared_task
from django.db import connection, transaction
from django.utils import timezone
from prometheus_client import Counter, Gauge

from .models import AuditEvent, Finding, FindingEvidence, Job, RiskAcceptance, Scan, Tenant
from .runner import analyze, analyzer_resources, analyzer_status, cleanup_resources
from .tenancy import tenant_context

logger = logging.getLogger(__name__)
LEASE_SECONDS = int(os.getenv("ANALYSIS_LEASE_SECONDS", "45"))
MAX_ATTEMPTS = int(os.getenv("ANALYSIS_MAX_ATTEMPTS", "3"))
STALE_JOBS = Gauge("trishul_stale_jobs", "Jobs whose durable lease has expired")
RECOVERIES = Counter("trishul_job_recoveries_total", "Job recovery decisions", ["decision"])


def _database_tenant(tenant_id):
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])


def _lease_deadline():
    return timezone.now() + timedelta(seconds=LEASE_SECONDS)


def _audit(job, action, details):
    AuditEvent.append(
        tenant=job.tenant,
        actor_type="system",
        actor_id="job-reconciler",
        action=action,
        resource_type="core.job",
        resource_id=job.id,
        details=details,
    )


@shared_task(name="core.tasks.execute_scan", acks_late=True)
def execute_scan(tenant_id, scan_id):
    token = uuid.uuid4()
    with transaction.atomic(), tenant_context(tenant_id):
        _database_tenant(tenant_id)
        job = Job.objects.select_for_update().get(kind="scan", payload__scan_id=str(scan_id))
        # Redelivery is expected. Only a queued job can acquire a new fenced lease.
        if job.state != Job.State.QUEUED:
            return
        scan = Scan.objects.select_for_update().select_related("repository_version").get(pk=scan_id)
        if scan.state not in (Scan.State.QUEUED, Scan.State.RUNNING):
            return
        container, scratch = analyzer_resources(scan_id)
        now = timezone.now()
        job.state = Job.State.RUNNING
        job.attempts += 1
        job.lease_token = token
        job.heartbeat_at = now
        job.lease_expires_at = _lease_deadline()
        job.analyzer_ref = container
        job.scratch_ref = scratch
        job.error_code = ""
        job.version += 1
        job.save()
        scan.state = Scan.State.RUNNING
        scan.version += 1
        scan.save(update_fields=["state", "version", "updated_at"])

    def heartbeat():
        now = timezone.now()
        updated = Job.all_objects.filter(
            pk=job.id, state=Job.State.RUNNING, lease_token=token
        ).update(heartbeat_at=now, lease_expires_at=now + timedelta(seconds=LEASE_SECONDS))
        if not updated:
            raise RuntimeError("analysis lease was lost")

    try:
        result = analyze(repository_version=scan.repository_version, scan_id=scan.id, heartbeat=heartbeat)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            job = Job.objects.select_for_update().get(pk=job.id)
            if job.state != Job.State.RUNNING or job.lease_token != token:
                raise RuntimeError("analysis result belongs to an obsolete lease")
            scan = Scan.objects.select_for_update().get(pk=scan_id)
            for item in result["findings"]:
                finding = Finding.all_objects.create(
                    tenant_id=tenant_id, scan=scan, rule_id=item["rule_id"],
                    rule_version=item["rule_version"], language="python", title=item["title"],
                    description=item["description"], cwe=item["cwe"], asvs=item["asvs"],
                    severity=item["severity"], confidence=item["confidence"], status=item["status"],
                    remediation=item["remediation"], fingerprint=item["fingerprint"],
                )
                FindingEvidence.all_objects.create(
                    tenant_id=tenant_id, finding=finding, file_path=item["file_path"],
                    start_line=item["start_line"], end_line=item["end_line"], snippet_hash=item["snippet_hash"],
                )
            scan.coverage = result["coverage"]
            scan.state = Scan.State.COMPLETED
            scan.version += 1
            scan.save(update_fields=["coverage", "state", "version", "updated_at"])
            job.state = Job.State.COMPLETED
            job.lease_expires_at = None
            job.lease_token = None
            job.version += 1
            job.save(update_fields=["state", "lease_expires_at", "lease_token", "version", "updated_at"])
            AuditEvent.append(
                tenant=scan.tenant, actor_type="system", actor_id="analysis-controller",
                action="scan.completed", resource_type="core.scan", resource_id=scan.id,
                details={"findings": len(result["findings"]), "pack": result["pack"],
                         "pack_version": result["pack_version"]},
            )
    except Exception as exc:
        logger.exception("Scan failed for %s", scan_id)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            current = Job.objects.select_for_update().get(pk=job.id)
            # Do not let an old/redelivered controller overwrite a newer recovery attempt.
            if current.lease_token == token:
                Scan.objects.filter(pk=scan_id).update(state=Scan.State.FAILED, version=scan.version + 1)
                current.state = Job.State.FAILED
                current.error_code = type(exc).__name__[:80]
                current.lease_expires_at = None
                current.lease_token = None
                current.version += 1
                current.save()
        raise


@shared_task(name="core.tasks.reconcile_jobs")
def reconcile_jobs():
    now = timezone.now()
    stale_count = 0
    dispatches = []
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        # Inspect outside a database transaction: runtime APIs may be unavailable or slow.
        with tenant_context(tenant_id):
            candidates = list(Job.objects.filter(state=Job.State.RUNNING, lease_expires_at__lt=now))
        stale_count += len(candidates)
        for candidate in candidates:
            scan_id = candidate.payload.get("scan_id")
            status = analyzer_status(scan_id)
            with transaction.atomic(), tenant_context(tenant_id):
                _database_tenant(tenant_id)
                job = Job.objects.select_for_update().select_related("tenant").get(pk=candidate.pk)
                if job.state != Job.State.RUNNING or not job.lease_expires_at or job.lease_expires_at >= now:
                    continue
                if status in ("active", "unknown"):
                    # Unknown is deliberately fail-closed: never launch a possible second analyzer.
                    job.lease_expires_at = _lease_deadline()
                    job.error_code = "runtime_unreachable" if status == "unknown" else "controller_lost"
                    job.version += 1
                    job.save(update_fields=["lease_expires_at", "error_code", "version", "updated_at"])
                    _audit(job, "job.recovery_deferred", {"runtime_status": status, "attempt": job.attempts})
                    RECOVERIES.labels(decision="deferred").inc()
                    continue
                # Only confirmed-inactive resources are safe to clean or replace.
                try:
                    cleanup_resources(scan_id)
                except Exception:
                    logger.exception("Could not clean resources for job %s", job.id)
                    job.lease_expires_at = _lease_deadline()
                    job.error_code = "cleanup_failed"
                    job.save(update_fields=["lease_expires_at", "error_code", "updated_at"])
                    _audit(job, "job.recovery_deferred", {"runtime_status": "inactive", "cleanup": "failed"})
                    RECOVERIES.labels(decision="deferred").inc()
                    continue
                job.lease_token = None
                job.lease_expires_at = None
                job.heartbeat_at = None
                job.version += 1
                if job.attempts < MAX_ATTEMPTS:
                    job.state = Job.State.QUEUED
                    job.error_code = "lease_expired_reclaimed"
                    Scan.objects.filter(pk=scan_id, state=Scan.State.RUNNING).update(state=Scan.State.QUEUED)
                    dispatches.append((str(tenant_id), str(scan_id)))
                    action, decision = "job.reclaimed", "reclaimed"
                else:
                    job.state = Job.State.FAILED
                    job.error_code = "infrastructure_failure"
                    Scan.objects.filter(pk=scan_id).update(state=Scan.State.FAILED)
                    action, decision = "job.infrastructure_failed", "exhausted"
                job.save()
                _audit(job, action, {"runtime_status": "inactive", "attempt": job.attempts})
                RECOVERIES.labels(decision=decision).inc()
    STALE_JOBS.set(stale_count)
    for tenant_id, scan_id in dispatches:
        execute_scan.apply_async(args=[tenant_id, scan_id], queue="analysis")


@shared_task(name="core.tasks.expire_acceptances")
def expire_acceptances():
    now = timezone.now()
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            RiskAcceptance.objects.filter(status="approved", expires_at__lte=now).update(status="expired")
