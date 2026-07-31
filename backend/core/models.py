import hashlib
import json
import secrets
import uuid
from pathlib import PurePosixPath

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.utils import timezone

from .tenancy import current_tenant_id


class TenantManager(models.Manager):
    def get_queryset(self):
        tenant_id = current_tenant_id()
        queryset = super().get_queryset()
        return queryset.filter(tenant_id=tenant_id) if tenant_id else queryset.none()


class UUIDModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    version = models.PositiveIntegerField(default=1)

    class Meta:
        abstract = True


class Tenant(UUIDModel):
    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=200)
    is_active = models.BooleanField(default=True)
    retention_days = models.PositiveIntegerField(default=365)

    def __str__(self):
        return self.name


class TenantScopedModel(UUIDModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT)
    objects = TenantManager()
    all_objects = models.Manager()

    class Meta:
        abstract = True
        base_manager_name = "all_objects"

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            related_model = getattr(field, "related_model", None)
            if (
                related_model
                and isinstance(related_model, type)
                and issubclass(related_model, TenantScopedModel)
                and getattr(self, field.attname, None)
            ):
                related = getattr(self, field.name)
                if related.tenant_id != self.tenant_id:
                    raise ValidationError({field.name: "Cross-tenant relationships are forbidden."})

    def save(self, *args, **kwargs):
        active_tenant = current_tenant_id()
        if active_tenant and self.tenant_id != active_tenant:
            raise ValidationError("Object tenant does not match the active tenant.")
        self.full_clean()
        return super().save(*args, **kwargs)


class Organization(TenantScopedModel):
    name = models.CharField(max_length=200)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "name"], name="organization_tenant_name_uniq")]


class Workspace(TenantScopedModel):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    name = models.CharField(max_length=200)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "organization", "name"], name="workspace_org_name_uniq")
        ]


class Application(TenantScopedModel):
    workspace = models.ForeignKey(Workspace, on_delete=models.PROTECT)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=4000)
    criticality = models.PositiveSmallIntegerField(default=3, validators=[MinValueValidator(0), MaxValueValidator(5)])
    data_sensitivity = models.PositiveSmallIntegerField(
        default=3, validators=[MinValueValidator(0), MaxValueValidator(5)]
    )
    internet_exposed = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "workspace", "name"], name="application_workspace_name_uniq")
        ]


class Membership(TenantScopedModel):
    class Role(models.TextChoices):
        ADMIN = "admin", "Organization administrator"
        CISO = "ciso", "Security leader"
        ARCHITECT = "architect", "Security architect"
        APPSEC = "appsec", "Application security engineer"
        ASSESSOR = "assessor", "Security assessor"
        DEVELOPER = "developer", "Developer"
        MANAGER = "manager", "Engineering manager"
        AUDITOR = "auditor", "Auditor"
        EXECUTIVE = "executive", "Executive"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=Role.choices)
    extra_permissions = models.JSONField(default=list, blank=True)
    application_ids = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "user"], name="membership_tenant_user_uniq")]


class ServiceAccount(TenantScopedModel):
    name = models.CharField(max_length=120)
    token_hash = models.CharField(max_length=64, unique=True)
    scopes = models.JSONField(default=list)
    application_ids = models.JSONField(default=list, blank=True)
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, *, tenant, name, scopes, expires_at, application_ids=()):
        account_id = uuid.uuid4()
        token = f"trishul.{account_id}.{secrets.token_urlsafe(32)}"
        account = cls.all_objects.create(
            id=account_id,
            tenant=tenant,
            name=name,
            scopes=scopes,
            application_ids=list(application_ids),
            expires_at=expires_at,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
        )
        return account, token


class AuditEvent(TenantScopedModel):
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    action = models.CharField(max_length=120)
    resource_type = models.CharField(max_length=80)
    resource_id = models.CharField(max_length=200)
    details = models.JSONField(default=dict)
    occurred_at = models.DateTimeField(default=timezone.now)
    previous_hash = models.CharField(max_length=64, blank=True)
    event_hash = models.CharField(max_length=64)

    class Meta:
        ordering = ["-occurred_at", "-id"]

    @classmethod
    def append(cls, *, tenant, actor_type, actor_id, action, resource_type, resource_id, details=None):
        details = details or {}
        with transaction.atomic():
            previous = cls.all_objects.select_for_update().filter(tenant=tenant).order_by("-occurred_at", "-id").first()
            occurred_at = timezone.now()
            previous_hash = previous.event_hash if previous else ""
            payload = json.dumps(
                {
                    "tenant": str(tenant.id),
                    "actor_type": actor_type,
                    "actor_id": actor_id,
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": str(resource_id),
                    "details": details,
                    "occurred_at": occurred_at.isoformat(),
                    "previous_hash": previous_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            return cls.all_objects.create(
                tenant=tenant,
                actor_type=actor_type,
                actor_id=actor_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                occurred_at=occurred_at,
                previous_hash=previous_hash,
                event_hash=hashlib.sha256(payload.encode()).hexdigest(),
            )

    def save(self, *args, **kwargs):
        if self.pk and AuditEvent.all_objects.filter(pk=self.pk).exists():
            raise ValidationError("Audit events are immutable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Audit events are immutable.")


class Repository(TenantScopedModel):
    application = models.ForeignKey(Application, on_delete=models.PROTECT)
    name = models.CharField(max_length=200)
    source_type = models.CharField(max_length=30, default="upload")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "application", "name"], name="repository_application_name_uniq")
        ]


class RepositoryVersion(TenantScopedModel):
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    object_key = models.CharField(max_length=600)
    sha256 = models.CharField(max_length=64)
    size = models.PositiveBigIntegerField()
    manifest = models.JSONField(default=dict)
    immutable = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "repository", "sha256"], name="repository_version_hash_uniq")
        ]


class Job(TenantScopedModel):
    class State(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    kind = models.CharField(max_length=50)
    application = models.ForeignKey(Application, on_delete=models.PROTECT, null=True, blank=True)
    state = models.CharField(max_length=20, choices=State.choices, default=State.QUEUED)
    payload = models.JSONField(default=dict)
    attempts = models.PositiveSmallIntegerField(default=0)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    error_code = models.CharField(max_length=80, blank=True)


class Scan(TenantScopedModel):
    class State(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        VALIDATING = "validating", "Validating"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    repository_version = models.ForeignKey(RepositoryVersion, on_delete=models.PROTECT)
    state = models.CharField(max_length=20, choices=State.choices, default=State.QUEUED)
    language_pack = models.CharField(max_length=100)
    language_pack_version = models.CharField(max_length=40)
    coverage = models.JSONField(default=dict)


class Finding(TenantScopedModel):
    class Status(models.TextChoices):
        CANDIDATE = "candidate", "Candidate"
        NEEDS_VALIDATION = "needs_validation", "Needs validation"
        CONFIRMED = "confirmed", "Confirmed"
        FALSE_POSITIVE = "false_positive", "False positive"
        REMEDIATION_PENDING = "remediation_pending", "Remediation pending"
        RESOLVED = "resolved", "Resolved"

    class AnalystDecision(models.TextChoices):
        ACCEPTED = "accepted", "Accepted"
        FALSE_POSITIVE = "false_positive", "False positive"
        DUPLICATE = "duplicate", "Duplicate"
        NEEDS_CONTEXT = "needs_context", "Needs context"

    scan = models.ForeignKey(Scan, on_delete=models.PROTECT)
    repository_version = models.ForeignKey(RepositoryVersion, on_delete=models.PROTECT)
    rule_id = models.CharField(max_length=160)
    rule_version = models.CharField(max_length=40)
    analyzer_name = models.CharField(max_length=160)
    analyzer_version = models.CharField(max_length=80)
    analyzer_image_digest = models.CharField(max_length=160, blank=True)
    language = models.CharField(max_length=60)
    framework = models.CharField(max_length=100, blank=True)
    title = models.CharField(max_length=300)
    description = models.TextField(max_length=8000)
    cwe = models.CharField(max_length=30, blank=True)
    asvs = models.CharField(max_length=60, blank=True)
    severity = models.PositiveSmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(5)])
    confidence = models.PositiveSmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(5)])
    status = models.CharField(max_length=30, choices=Status.choices, default=Status.CANDIDATE)
    validation_notes = models.TextField(blank=True, max_length=8000)
    remediation = models.TextField(blank=True, max_length=8000)
    fingerprint = models.CharField(max_length=64)
    file_path = models.CharField(max_length=600)
    start_line = models.PositiveIntegerField()
    end_line = models.PositiveIntegerField()
    evidence = models.JSONField()
    analyst_decision = models.CharField(
        max_length=30, choices=AnalystDecision.choices, default=AnalystDecision.NEEDS_CONTEXT
    )
    decision_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "scan", "fingerprint"], name="finding_scan_fingerprint_uniq")
        ]

    def clean(self):
        super().clean()
        if self.scan_id and self.repository_version_id != self.scan.repository_version_id:
            raise ValidationError({"repository_version": "Must identify the immutable version used by the scan."})
        path = PurePosixPath(self.file_path)
        if not self.file_path or path.is_absolute() or ".." in path.parts or "\\" in self.file_path:
            raise ValidationError({"file_path": "Use a normalized relative POSIX path."})
        normalized = path.as_posix()
        if normalized != self.file_path or normalized in {"", "."}:
            raise ValidationError({"file_path": "Use a normalized relative POSIX path."})
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValidationError({"end_line": "Line ranges must be positive and end at or after start_line."})
        if not isinstance(self.evidence, dict) or not self.evidence:
            raise ValidationError({"evidence": "Structured evidence is required to reproduce the match."})

    def save(self, *args, **kwargs):
        if self.pk:
            original = Finding.all_objects.filter(pk=self.pk).values(
                "tenant_id", "scan_id", "repository_version_id", "rule_id", "rule_version",
                "analyzer_name", "analyzer_version", "analyzer_image_digest", "file_path",
                "start_line", "end_line", "evidence", "fingerprint", "created_at",
            ).first()
            if original:
                for field, value in original.items():
                    if getattr(self, field) != value:
                        raise ValidationError({field: "Finding provenance is immutable."})
        return super().save(*args, **kwargs)


class FindingEvidence(TenantScopedModel):
    finding = models.ForeignKey(Finding, on_delete=models.PROTECT, related_name="evidence_records")
    file_path = models.CharField(max_length=600)
    start_line = models.PositiveIntegerField()
    end_line = models.PositiveIntegerField()
    snippet_hash = models.CharField(max_length=64)
    object_key = models.CharField(max_length=600, blank=True)


class ThreatModel(TenantScopedModel):
    application = models.ForeignKey(Application, on_delete=models.PROTECT)
    name = models.CharField(max_length=200)
    revision = models.PositiveIntegerField(default=1)
    verified = models.BooleanField(default=False)


class ArchitectureComponent(TenantScopedModel):
    threat_model = models.ForeignKey(ThreatModel, on_delete=models.PROTECT, related_name="components")
    name = models.CharField(max_length=200)
    component_type = models.CharField(max_length=80)
    trust_boundary = models.CharField(max_length=200, blank=True)
    data_classification = models.CharField(max_length=80, blank=True)
    verified = models.BooleanField(default=False)


class DataFlow(TenantScopedModel):
    threat_model = models.ForeignKey(ThreatModel, on_delete=models.PROTECT, related_name="data_flows")
    source = models.ForeignKey(ArchitectureComponent, on_delete=models.PROTECT, related_name="outbound_flows")
    destination = models.ForeignKey(ArchitectureComponent, on_delete=models.PROTECT, related_name="inbound_flows")
    protocol = models.CharField(max_length=80)
    encrypted = models.BooleanField(default=True)
    authenticated = models.BooleanField(default=True)
    verified = models.BooleanField(default=False)


class Threat(TenantScopedModel):
    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        OPEN = "open", "Open"
        MITIGATED = "mitigated", "Mitigated"
        ACCEPTED = "accepted", "Accepted"
        CLOSED = "closed", "Closed"

    threat_model = models.ForeignKey(ThreatModel, on_delete=models.PROTECT, related_name="threats")
    component = models.ForeignKey(ArchitectureComponent, on_delete=models.PROTECT, null=True, blank=True)
    stride_category = models.CharField(max_length=40)
    scenario = models.TextField(max_length=8000)
    affected_assets = models.JSONField(default=list)
    controls = models.JSONField(default=list)
    likelihood = models.PositiveSmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(5)])
    impact = models.PositiveSmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(5)])
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)


class FrameworkVersion(TenantScopedModel):
    framework = models.CharField(max_length=120)
    version_name = models.CharField(max_length=80)
    source_url = models.URLField()
    catalog_hash = models.CharField(max_length=64)
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "framework", "version_name"], name="framework_version_uniq")
        ]


class Requirement(TenantScopedModel):
    framework_version = models.ForeignKey(FrameworkVersion, on_delete=models.PROTECT, related_name="requirements")
    control_id = models.CharField(max_length=80)
    title = models.CharField(max_length=300)
    requirement = models.TextField(max_length=12000)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "framework_version", "control_id"], name="requirement_control_uniq"
            )
        ]


class Assessment(TenantScopedModel):
    application = models.ForeignKey(Application, on_delete=models.PROTECT)
    framework_version = models.ForeignKey(FrameworkVersion, on_delete=models.PROTECT)
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=30, default="draft")


class Evidence(TenantScopedModel):
    assessment = models.ForeignKey(Assessment, on_delete=models.PROTECT, related_name="evidence")
    title = models.CharField(max_length=300)
    source = models.CharField(max_length=600)
    evidence_date = models.DateField()
    object_key = models.CharField(max_length=600)
    sha256 = models.CharField(max_length=64)
    classification = models.CharField(max_length=80)
    immutable = models.BooleanField(default=True)


class AssessmentResponse(TenantScopedModel):
    class Decision(models.TextChoices):
        UNANSWERED = "unanswered", "Unanswered"
        DRAFT = "draft", "Draft"
        COMPLIANT = "compliant", "Compliant"
        PARTIAL = "partial", "Partial"
        NONCOMPLIANT = "noncompliant", "Noncompliant"
        NOT_APPLICABLE = "not_applicable", "Not applicable"

    assessment = models.ForeignKey(Assessment, on_delete=models.PROTECT, related_name="responses")
    requirement = models.ForeignKey(Requirement, on_delete=models.PROTECT)
    evidence = models.ManyToManyField(Evidence, through="AssessmentEvidence", blank=True)
    decision = models.CharField(max_length=30, choices=Decision.choices, default=Decision.UNANSWERED)
    rationale = models.TextField(blank=True, max_length=8000)
    confidence = models.PositiveSmallIntegerField(default=0, validators=[MinValueValidator(0), MaxValueValidator(5)])
    review_status = models.CharField(max_length=30, default="pending")
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)


class AssessmentEvidence(TenantScopedModel):
    response = models.ForeignKey(AssessmentResponse, on_delete=models.PROTECT)
    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "response", "evidence"], name="assessment_evidence_uniq")
        ]


class ComplianceGap(TenantScopedModel):
    response = models.ForeignKey(AssessmentResponse, on_delete=models.PROTECT)
    description = models.TextField(max_length=8000)
    corrective_action = models.TextField(max_length=8000)
    status = models.CharField(max_length=30, default="open")


class Risk(TenantScopedModel):
    application = models.ForeignKey(Application, on_delete=models.PROTECT)
    title = models.CharField(max_length=300)
    description = models.TextField(max_length=8000)
    state = models.CharField(max_length=30, default="open")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)


class RiskLink(TenantScopedModel):
    risk = models.ForeignKey(Risk, on_delete=models.PROTECT, related_name="links")
    relationship = models.CharField(max_length=40)
    source_type = models.CharField(max_length=60)
    source_id = models.UUIDField()


class RiskScore(TenantScopedModel):
    risk = models.ForeignKey(Risk, on_delete=models.PROTECT, related_name="scores")
    formula_version = models.CharField(max_length=30, default="1.0")
    inputs = models.JSONField()
    inherent = models.DecimalField(max_digits=5, decimal_places=2)
    residual = models.DecimalField(max_digits=5, decimal_places=2)
    priority = models.DecimalField(max_digits=5, decimal_places=2)
    computed_at = models.DateTimeField(default=timezone.now)


class Remediation(TenantScopedModel):
    risk = models.ForeignKey(Risk, on_delete=models.PROTECT, related_name="remediations")
    description = models.TextField(max_length=8000)
    status = models.CharField(max_length=30, default="planned")
    due_at = models.DateTimeField(null=True, blank=True)


class RiskAcceptance(TenantScopedModel):
    risk = models.ForeignKey(Risk, on_delete=models.PROTECT)
    rationale = models.TextField(max_length=8000)
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=30, default="pending")
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="risk_acceptance_requests"
    )


class Approval(TenantScopedModel):
    acceptance = models.ForeignKey(RiskAcceptance, on_delete=models.PROTECT, related_name="approvals")
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    decision = models.CharField(max_length=20)
    reason = models.TextField(max_length=4000)

    def clean(self):
        super().clean()
        if self.acceptance_id and self.approver_id == self.acceptance.requested_by_id:
            raise ValidationError("Requesters cannot approve their own risk acceptance.")


class ModelConfiguration(TenantScopedModel):
    class EndpointType(models.TextChoices):
        OPENAI_COMPATIBLE = "openai_compatible", "OpenAI-compatible"
        PRIVATE_HTTP = "private_http", "Generic private HTTP"

    name = models.CharField(max_length=120)
    endpoint_type = models.CharField(max_length=30, choices=EndpointType.choices)
    endpoint_url = models.URLField()
    model_name = models.CharField(max_length=160)
    credential_reference = models.CharField(max_length=300, blank=True)
    ca_bundle_path = models.CharField(max_length=300, blank=True)
    allowed_data_classes = models.JSONField(default=list)
    max_context_tokens = models.PositiveIntegerField(default=32768)
    max_output_tokens = models.PositiveIntegerField(default=4096)
    requests_per_minute = models.PositiveSmallIntegerField(default=30)
    daily_token_limit = models.PositiveIntegerField(default=1_000_000)
    timeout_seconds = models.PositiveSmallIntegerField(default=60)
    is_active = models.BooleanField(default=True)


class PromptVersion(TenantScopedModel):
    workflow = models.CharField(max_length=80)
    version_name = models.CharField(max_length=40)
    template_hash = models.CharField(max_length=64)
    approved_at = models.DateTimeField(null=True, blank=True)


class AIAnalysisRun(TenantScopedModel):
    model_configuration = models.ForeignKey(ModelConfiguration, on_delete=models.PROTECT)
    prompt_version = models.ForeignKey(PromptVersion, on_delete=models.PROTECT)
    workflow = models.CharField(max_length=80)
    state = models.CharField(max_length=30, default="queued")
    request_hash = models.CharField(max_length=64)
    response_hash = models.CharField(max_length=64, blank=True)
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)
    policy_decisions = models.JSONField(default=list)
    error_code = models.CharField(max_length=80, blank=True)


class Report(TenantScopedModel):
    application = models.ForeignKey(Application, on_delete=models.PROTECT)
    report_type = models.CharField(max_length=40)
    object_key = models.CharField(max_length=600)
    content_hash = models.CharField(max_length=64)
    source_versions = models.JSONField(default=dict)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
