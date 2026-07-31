import logging
from pathlib import PurePosixPath

from celery import shared_task
from django.db import connection, transaction
from django.utils import timezone
from rest_framework import serializers

from .models import AuditEvent, Finding, FindingEvidence, Job, RiskAcceptance, Scan, Tenant
from .runner import analyze
from .tenancy import tenant_context

logger = logging.getLogger(__name__)


class AnalyzerFindingSerializer(serializers.Serializer):
    rule_id = serializers.CharField(max_length=160)
    rule_version = serializers.CharField(max_length=40)
    analyzer_name = serializers.CharField(max_length=160)
    analyzer_version = serializers.CharField(max_length=80, allow_blank=True)
    analyzer_image_digest = serializers.CharField(max_length=160, allow_blank=True)
    title = serializers.CharField(max_length=300)
    description = serializers.CharField(max_length=8000)
    cwe = serializers.CharField(max_length=30, allow_blank=True)
    asvs = serializers.CharField(max_length=60, allow_blank=True)
    severity = serializers.IntegerField(min_value=0, max_value=5)
    confidence = serializers.IntegerField(min_value=0, max_value=5)
    status = serializers.ChoiceField(choices=Finding.Status.choices)
    remediation = serializers.CharField(max_length=8000, allow_blank=False)
    fingerprint = serializers.RegexField(r"^[0-9a-f]{64}$")
    file_path = serializers.CharField(max_length=600)
    start_line = serializers.IntegerField(min_value=1)
    end_line = serializers.IntegerField(min_value=1)
    snippet_hash = serializers.RegexField(r"^[0-9a-f]{64}$")
    evidence = serializers.DictField(allow_empty=False)

    def validate(self, attrs):
        path = PurePosixPath(attrs["file_path"])
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in attrs["file_path"]
            or path.as_posix() != attrs["file_path"]
        ):
            raise serializers.ValidationError({"file_path": "Use a normalized relative POSIX path."})
        if attrs["end_line"] < attrs["start_line"]:
            raise serializers.ValidationError({"end_line": "Must be at or after start_line."})
        if not attrs["analyzer_version"] and not attrs["analyzer_image_digest"]:
            raise serializers.ValidationError("An analyzer version or image digest is required.")
        if attrs["evidence"].get("snippet_sha256") != attrs["snippet_hash"]:
            raise serializers.ValidationError({"evidence": "Evidence must identify the matched snippet."})
        return attrs


def validate_analyzer_output(result):
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("coverage"), dict)
        or not result.get("pack")
        or not result.get("pack_version")
        or not isinstance(result.get("analyzer"), dict)
    ):
        raise serializers.ValidationError("Analyzer output must include pack, analyzer, and coverage metadata.")
    serializer = AnalyzerFindingSerializer(data=result.get("findings"), many=True)
    serializer.is_valid(raise_exception=True)
    analyzer = result["analyzer"]
    if not analyzer.get("name") or (not analyzer.get("version") and not analyzer.get("image_digest")):
        raise serializers.ValidationError("Analyzer identity requires a name and version or image digest.")
    for finding in serializer.validated_data:
        if any(
            finding[field] != analyzer.get(metadata_field, "")
            for field, metadata_field in (
                ("analyzer_name", "name"),
                ("analyzer_version", "version"),
                ("analyzer_image_digest", "image_digest"),
            )
        ):
            raise serializers.ValidationError("Finding analyzer identity does not match output metadata.")
    return serializer.validated_data


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
    try:
        result = analyze(repository_version=scan.repository_version, scan_id=scan.id)
        validated_findings = validate_analyzer_output(result)
        with transaction.atomic(), tenant_context(tenant_id):
            _database_tenant(tenant_id)
            scan = Scan.objects.select_for_update().get(pk=scan_id)
            for item in validated_findings:
                finding = Finding.all_objects.create(
                    tenant_id=tenant_id,
                    scan=scan,
                    repository_version=scan.repository_version,
                    rule_id=item["rule_id"],
                    rule_version=item["rule_version"],
                    analyzer_name=item["analyzer_name"],
                    analyzer_version=item["analyzer_version"],
                    analyzer_image_digest=item["analyzer_image_digest"],
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
                    file_path=item["file_path"],
                    start_line=item["start_line"],
                    end_line=item["end_line"],
                    evidence=item["evidence"],
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
            AuditEvent.append(
                tenant=scan.tenant,
                actor_type="system",
                actor_id="analysis-controller",
                action="scan.completed",
                resource_type="core.scan",
                resource_id=scan.id,
                details={
                    "findings": len(validated_findings),
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
