import logging
from datetime import timedelta

from celery import shared_task
from django.db import connection, transaction
from django.db.models import F
from django.utils import timezone

from .git_fetch import persist_version, publish_status
from .models import AuditEvent, Finding, FindingEvidence, Job, Repository, RiskAcceptance, Scan, Tenant
from .runner import analyze
from .tenancy import tenant_context

logger = logging.getLogger(__name__)


def _database_tenant(tenant_id):
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])


@shared_task(name="core.tasks.execute_scan", acks_late=True)
def execute_scan(tenant_id, scan_id):
    with transaction.atomic(), tenant_context(tenant_id):
        _database_tenant(tenant_id)
        scan = Scan.objects.select_for_update().select_related("repository_version").get(pk=scan_id)
        if scan.state != Scan.State.QUEUED:
            return
        scan.state = Scan.State.RUNNING
        scan.version += 1
        scan.save(update_fields=["state", "version", "updated_at"])
        Job.objects.filter(payload__scan_id=str(scan_id), state=Job.State.QUEUED).update(
            state=Job.State.RUNNING,
            attempts=F("attempts") + 1,
            lease_expires_at=timezone.now() + timedelta(minutes=35),
        )
    try:
        result = analyze(repository_version=scan.repository_version, scan_id=scan.id, pack=scan.language_pack)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            scan = Scan.objects.select_for_update().get(pk=scan_id)
            for item in result["findings"]:
                finding = Finding.all_objects.create(
                    tenant_id=tenant_id,
                    scan=scan,
                    rule_id=item["rule_id"],
                    rule_version=item["rule_version"],
                    language=item.get("language") or scan.language_pack,
                    title=item["title"],
                    description=item["description"],
                    cwe=item["cwe"],
                    asvs=item["asvs"],
                    severity=item["severity"],
                    confidence=item["confidence"],
                    status=(
                        item["status"]
                        if item["status"] in {Finding.Status.CANDIDATE, Finding.Status.NEEDS_VALIDATION}
                        else Finding.Status.NEEDS_VALIDATION
                    ),
                    remediation=item["remediation"],
                    fingerprint=item["fingerprint"],
                )
                for evidence in item["evidence"]:
                    location = evidence.get("location", {})
                    FindingEvidence.all_objects.create(
                        tenant_id=tenant_id,
                        finding=finding,
                        evidence_type=evidence["evidence_type"],
                        location=location,
                        file_path=evidence.get("file_path", location.get("file_path", "")),
                        start_line=evidence.get("start_line", location.get("start_line", 0)),
                        end_line=evidence.get("end_line", location.get("end_line", 0)),
                        snippet_hash=evidence.get("snippet_hash", location.get("snippet_hash", "")),
                    )
            scan.coverage = result["coverage"]
            scan.state = Scan.State.COMPLETED
            scan.version += 1
            scan.save(update_fields=["coverage", "state", "version", "updated_at"])
            Job.objects.filter(payload__scan_id=str(scan_id)).update(
                state=Job.State.COMPLETED, lease_expires_at=None
            )
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
        publish_advisory_status.apply_async(args=[str(tenant_id), str(scan.repository_version_id)], queue="git-fetch")
    except Exception as exc:
        logger.exception("Scan failed for %s", scan_id)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            Scan.objects.filter(pk=scan_id).update(state=Scan.State.FAILED, version=scan.version + 1)
            Job.objects.filter(payload__scan_id=str(scan_id)).update(
                state=Job.State.FAILED, error_code=type(exc).__name__[:80], lease_expires_at=None
            )
        publish_advisory_status.apply_async(
            args=[str(tenant_id), str(scan.repository_version_id)], queue="git-fetch"
        )
        raise


def _create_scans(version):
    paths = [item["path"] for item in version.manifest.get("files", [])]
    packs = [("semgrep", "1.0"), ("trivy", "1.0")]
    if any(path.endswith(".py") for path in paths):
        packs.insert(0, ("python-stdlib", "1.0"))
    for pack, pack_version in packs:
        scan = Scan.all_objects.create(
            tenant=version.tenant,
            repository_version=version,
            language_pack=pack,
            language_pack_version=pack_version,
        )
        Job.all_objects.create(
            tenant=version.tenant,
            application=version.repository.application,
            kind="scan",
            payload={"scan_id": str(scan.id)},
        )
        execute_scan.apply_async(args=[str(version.tenant_id), str(scan.id)], queue="analysis")


@shared_task(name="core.tasks.fetch_repository", acks_late=True)
def fetch_repository(tenant_id, repository_id, commit_sha, ref="", event=None):
    event = event or {}
    with tenant_context(tenant_id):
        _database_tenant(tenant_id)
        repository = Repository.objects.select_related("application", "tenant").get(pk=repository_id)
        version, created = persist_version(repository, commit_sha, ref, event)
        if created:
            _create_scans(version)


@shared_task(name="core.tasks.publish_advisory_status", acks_late=True)
def publish_advisory_status(tenant_id, version_id):
    with tenant_context(tenant_id):
        _database_tenant(tenant_id)
        from .models import RepositoryVersion

        version = RepositoryVersion.objects.select_related("repository").get(pk=version_id)
        if version.repository.source_type == Repository.SourceType.UPLOAD:
            return
        scans = Scan.objects.filter(repository_version=version)
        if not scans.exists() or scans.exclude(state__in=[Scan.State.COMPLETED, Scan.State.FAILED]).exists():
            return
        publish_status(version, Finding.objects.filter(scan__repository_version=version).count())


@shared_task(name="core.tasks.reconcile_jobs")
def reconcile_jobs():
    now = timezone.now()
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            stale = Job.objects.filter(state=Job.State.RUNNING, lease_expires_at__lt=now)
            for job in stale.select_for_update():
                retry = job.attempts < 3 and job.kind == "scan" and job.payload.get("scan_id")
                job.state = Job.State.QUEUED if retry else Job.State.FAILED
                job.error_code = "lease_expired"
                job.lease_expires_at = None
                job.version += 1
                job.save(update_fields=["state", "error_code", "lease_expires_at", "version", "updated_at"])
                if retry:
                    scan_id = job.payload["scan_id"]
                    Scan.objects.filter(pk=scan_id, state=Scan.State.RUNNING).update(state=Scan.State.QUEUED)
                    transaction.on_commit(
                        lambda tenant_id=tenant_id, scan_id=scan_id: execute_scan.apply_async(
                            args=[str(tenant_id), str(scan_id)], queue="analysis"
                        )
                    )
                elif job.kind == "scan" and job.payload.get("scan_id"):
                    Scan.objects.filter(pk=job.payload["scan_id"]).update(state=Scan.State.FAILED)


@shared_task(name="core.tasks.expire_acceptances")
def expire_acceptances():
    now = timezone.now()
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            RiskAcceptance.objects.filter(status="approved", expires_at__lte=now).update(status="expired")
