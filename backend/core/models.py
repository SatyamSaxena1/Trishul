import hashlib
import json
import secrets
import uuid
from urllib.parse import urlparse

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
    class Type(models.TextChoices):
        PLATFORM = "platform", "Platform"
        AUDIT_FIRM = "audit_firm", "Audit firm"
        AUDITEE = "auditee", "Auditee organisation"

    class AuditeeMode(models.TextChoices):
        FIRM_MANAGED = "firm_managed", "Firm managed"
        SELF_SERVICE = "self_service", "Self service"

    class IsolationTier(models.TextChoices):
        SHARED = "shared", "Shared SaaS"
        ENTERPRISE = "enterprise", "Enterprise isolated SaaS"
        DEDICATED = "dedicated", "Dedicated/private"

    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=200)
    tenant_type = models.CharField(max_length=20, choices=Type.choices, default=Type.AUDITEE)
    auditee_mode = models.CharField(max_length=20, choices=AuditeeMode.choices, blank=True)
    isolation_tier = models.CharField(max_length=20, choices=IsolationTier.choices, default=IsolationTier.SHARED)
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
        PLATFORM_ADMIN = "platform_admin", "Platform administrator"
        FIRM_ADMIN = "firm_admin", "Audit firm administrator"
        AUDIT_MANAGER = "audit_manager", "Audit manager"
        REVIEWER = "reviewer", "Reviewer / QA"
        ORG_ADMIN = "org_admin", "Auditee administrator"
        COMPLIANCE_MANAGER = "compliance_manager", "Compliance manager"
        CONTROL_OWNER = "control_owner", "Control owner"
        RISK_OWNER = "risk_owner", "Risk owner"
        VENDOR_MANAGER = "vendor_manager", "Vendor manager"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=Role.choices)
    extra_permissions = models.JSONField(default=list, blank=True)
    application_ids = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "user"], name="membership_tenant_user_uniq")]


class TenantRelationship(TenantScopedModel):
    class Relationship(models.TextChoices):
        MANAGES = "manages", "Manages"
        CLIENT = "client", "Client"

    related_tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="incoming_relationships")
    relationship = models.CharField(max_length=20, choices=Relationship.choices)
    status = models.CharField(max_length=20, default="active")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "related_tenant", "relationship"], name="tenant_relationship_uniq"
            )
        ]


class SubscriptionPlan(TenantScopedModel):
    key = models.SlugField(max_length=80)
    plan_version = models.CharField(max_length=40, default="1.0")
    name = models.CharField(max_length=160)
    entitlements = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "key", "plan_version"], name="plan_version_uniq")]


class TenantSubscription(TenantScopedModel):
    class State(models.TextChoices):
        TRIAL = "trial", "Trial"
        ACTIVE = "active", "Active"
        GRACE = "grace", "Grace period"
        SUSPENDED = "suspended", "Suspended"
        EXPIRED = "expired", "Expired"

    plan_key = models.CharField(max_length=80)
    plan_version = models.CharField(max_length=40)
    entitlement_snapshot = models.JSONField(default=dict)
    state = models.CharField(max_length=20, choices=State.choices, default=State.TRIAL)
    trial_started_at = models.DateTimeField(null=True, blank=True)
    trial_ends_at = models.DateTimeField(null=True, blank=True)
    grace_ends_at = models.DateTimeField(null=True, blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)


class TenantEntitlement(TenantScopedModel):
    code = models.CharField(max_length=80)
    enabled = models.BooleanField(default=True)
    limit = models.PositiveBigIntegerField(null=True, blank=True)
    configuration = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "code"], name="tenant_entitlement_uniq")]


class UsageRecord(TenantScopedModel):
    metric = models.CharField(max_length=80)
    quantity = models.PositiveBigIntegerField()
    recorded_at = models.DateTimeField(default=timezone.now)
    idempotency_key = models.CharField(max_length=200, blank=True)
    source_type = models.CharField(max_length=100, blank=True)
    source_id = models.UUIDField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "idempotency_key"],
                condition=models.Q(idempotency_key__gt=""),
                name="usage_idempotency_uniq",
            )
        ]
        indexes = [models.Index(fields=["tenant", "metric", "recorded_at"], name="usage_metric_time_idx")]


class TenantBranding(TenantScopedModel):
    logo_object_key = models.CharField(max_length=600, blank=True)
    primary_color = models.CharField(max_length=7, default="#1d4ed8")
    report_name = models.CharField(max_length=160, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant"], name="tenant_branding_uniq")]


class IdentityProviderConfiguration(TenantScopedModel):
    class Protocol(models.TextChoices):
        OIDC = "oidc", "OpenID Connect"
        SAML = "saml", "SAML 2.0"

    protocol = models.CharField(max_length=10, choices=Protocol.choices)
    name = models.CharField(max_length=120)
    issuer = models.URLField()
    discovery_url = models.URLField(blank=True)
    client_id = models.CharField(max_length=200, blank=True)
    audience = models.CharField(max_length=200, blank=True)
    jwks_url = models.URLField(blank=True)
    metadata_url = models.URLField(blank=True)
    secret_reference = models.CharField(max_length=300, blank=True)
    attribute_mapping = models.JSONField(default=dict, blank=True)
    mfa_required = models.BooleanField(default=True)
    allowed_acr_values = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=False)
    validated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "protocol"], name="tenant_identity_protocol_uniq")]

    def clean(self):
        super().clean()
        if (
            self.enabled
            and self.protocol == self.Protocol.OIDC
            and not all((self.client_id, self.audience, self.jwks_url))
        ):
            raise ValidationError("Enabled OIDC configuration requires client_id, audience and jwks_url.")
        if self.enabled and self.protocol == self.Protocol.SAML and not self.metadata_url:
            raise ValidationError("Enabled SAML configuration requires metadata_url.")
        urls = [self.issuer]
        urls.extend([self.jwks_url, self.discovery_url] if self.protocol == self.Protocol.OIDC else [self.metadata_url])
        for value in filter(None, urls):
            parsed = urlparse(value)
            if parsed.scheme != "https" and not (settings.DEBUG and parsed.hostname in {"localhost", "127.0.0.1"}):
                raise ValidationError("Identity provider endpoints must use HTTPS.")


class TenantSessionPolicy(TenantScopedModel):
    idle_timeout_minutes = models.PositiveIntegerField(default=30, validators=[MinValueValidator(1)])
    absolute_timeout_minutes = models.PositiveIntegerField(default=720, validators=[MinValueValidator(1)])
    max_concurrent_sessions = models.PositiveSmallIntegerField(default=5, validators=[MinValueValidator(1)])
    require_mfa = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant"], name="tenant_session_policy_uniq")]

    def clean(self):
        super().clean()
        if self.idle_timeout_minutes > self.absolute_timeout_minutes:
            raise ValidationError({"idle_timeout_minutes": "Idle timeout cannot exceed the absolute timeout."})


class AuthSession(TenantScopedModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    started_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    absolute_expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["tenant", "user", "revoked_at"], name="auth_session_active_idx")]


class TenantInvitation(TenantScopedModel):
    target_tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="invitations")
    email = models.EmailField()
    role = models.CharField(max_length=30, choices=Membership.Role.choices)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)

    @classmethod
    def issue(cls, **values):
        token = secrets.token_urlsafe(32)
        return cls.objects.create(token_hash=hashlib.sha256(token.encode()).hexdigest(), **values), token


class ScimCredential(TenantScopedModel):
    name = models.CharField(max_length=120)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    default_role = models.CharField(max_length=30, choices=Membership.Role.choices)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, **values):
        token = secrets.token_urlsafe(32)
        return cls.objects.create(token_hash=hashlib.sha256(token.encode()).hexdigest(), **values), token


class ScimIdentity(TenantScopedModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    external_id = models.CharField(max_length=200, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "user"], name="scim_identity_tenant_user_uniq"),
            models.UniqueConstraint(
                fields=["tenant", "external_id"],
                condition=models.Q(external_id__gt=""),
                name="scim_identity_tenant_external_uniq",
            ),
        ]


class Engagement(TenantScopedModel):
    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        ACTIVE = "active", "Active"
        CLOSED = "closed", "Closed"
        REVOKED = "revoked", "Revoked"

    auditee_tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="audit_engagements")
    name = models.CharField(max_length=200)
    reference = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    starts_on = models.DateField()
    ends_on = models.DateField()
    framework_scope = models.JSONField(default=list)
    application_scope = models.JSONField(default=list, blank=True)
    control_scope = models.JSONField(default=list, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="engagements_created"
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="engagements_approved",
    )
    closed_reason = models.TextField(blank=True, max_length=4000)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "reference"], name="engagement_reference_uniq")]

    def clean(self):
        super().clean()
        if self.tenant_id and self.tenant.tenant_type != Tenant.Type.AUDIT_FIRM:
            raise ValidationError({"tenant": "Engagements must be owned by an audit-firm tenant."})
        if self.auditee_tenant_id and self.auditee_tenant.tenant_type != Tenant.Type.AUDITEE:
            raise ValidationError({"auditee_tenant": "An engagement target must be an auditee tenant."})
        if self.starts_on and self.ends_on and self.starts_on > self.ends_on:
            raise ValidationError({"ends_on": "The engagement end date must not precede its start date."})

    def is_live(self, on_date=None):
        on_date = on_date or timezone.localdate()
        return self.status == self.Status.ACTIVE and self.starts_on <= on_date <= self.ends_on


class EngagementScope(TenantScopedModel):
    class Type(models.TextChoices):
        FRAMEWORK = "framework", "Framework"
        APPLICATION = "application", "Application"
        CONTROL = "control", "Control"

    engagement = models.ForeignKey(Engagement, on_delete=models.PROTECT, related_name="scopes")
    scope_type = models.CharField(max_length=20, choices=Type.choices)
    object_reference = models.CharField(max_length=200)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "engagement", "scope_type", "object_reference"], name="engagement_scope_uniq"
            )
        ]


class EngagementMember(TenantScopedModel):
    class Role(models.TextChoices):
        LEAD = "lead", "Lead auditor"
        AUDITOR = "auditor", "Auditor"
        REVIEWER = "reviewer", "Reviewer / QA"

    engagement = models.ForeignKey(Engagement, on_delete=models.PROTECT, related_name="members")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    role = models.CharField(max_length=20, choices=Role.choices)
    framework_scope = models.JSONField(default=list, blank=True)
    control_scope = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "engagement", "user"], name="engagement_member_uniq")]


class ImmutableTenantRecord(TenantScopedModel):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.pk and type(self).all_objects.filter(pk=self.pk).exists():
            raise ValidationError(f"{self._meta.verbose_name_plural.title()} are immutable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError(f"{self._meta.verbose_name_plural.title()} are immutable.")


class EngagementStatusHistory(ImmutableTenantRecord):
    engagement = models.ForeignKey(Engagement, on_delete=models.PROTECT, related_name="status_history")
    from_status = models.CharField(max_length=20, blank=True)
    to_status = models.CharField(max_length=20, choices=Engagement.Status.choices)
    reason = models.TextField(blank=True, max_length=4000)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    occurred_at = models.DateTimeField(default=timezone.now)


class CrossTenantAccessEvent(ImmutableTenantRecord):
    target_tenant = models.ForeignKey(
        Tenant, on_delete=models.PROTECT, null=True, blank=True, related_name="cross_tenant_access_events"
    )
    engagement = models.ForeignKey(Engagement, on_delete=models.PROTECT, null=True, blank=True)
    subject_id = models.CharField(max_length=200)
    object_type = models.CharField(max_length=100)
    object_id = models.CharField(max_length=200, blank=True)
    action = models.CharField(max_length=80)
    decision = models.CharField(max_length=20, choices=[("allow", "Allow"), ("deny", "Deny")])
    reason = models.CharField(max_length=300)
    occurred_at = models.DateTimeField(default=timezone.now)


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

    scan = models.ForeignKey(Scan, on_delete=models.PROTECT)
    rule_id = models.CharField(max_length=160)
    rule_version = models.CharField(max_length=40)
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

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "scan", "fingerprint"], name="finding_scan_fingerprint_uniq")
        ]


class FindingEvidence(TenantScopedModel):
    finding = models.ForeignKey(Finding, on_delete=models.PROTECT, related_name="evidence")
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
    framework_record = models.ForeignKey(
        "Framework", on_delete=models.PROTECT, null=True, blank=True, related_name="versions"
    )
    framework = models.CharField(max_length=120)
    version_name = models.CharField(max_length=80)
    source_url = models.URLField()
    catalog_hash = models.CharField(max_length=64)
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "framework", "version_name"], name="framework_version_uniq")
        ]


class Framework(TenantScopedModel):
    code = models.SlugField(max_length=80)
    name = models.CharField(max_length=200)
    issuing_body = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, default="published")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "code"], name="framework_code_uniq")]


class Requirement(TenantScopedModel):
    class Criticality(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    framework_version = models.ForeignKey(FrameworkVersion, on_delete=models.PROTECT, related_name="requirements")
    control_id = models.CharField(max_length=80)
    title = models.CharField(max_length=300)
    requirement = models.TextField(max_length=12000)
    criticality = models.CharField(max_length=20, choices=Criticality.choices, default=Criticality.MEDIUM)
    testing_guidance = models.TextField(max_length=4000, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "framework_version", "control_id"], name="requirement_control_uniq"
            )
        ]


class UnifiedControlObjective(TenantScopedModel):
    class ControlType(models.TextChoices):
        PREVENTIVE = "preventive", "Preventive"
        DETECTIVE = "detective", "Detective"
        CORRECTIVE = "corrective", "Corrective"

    class Nature(models.TextChoices):
        TECHNICAL = "technical", "Technical"
        PROCESS = "process", "Process"
        DOCUMENTATION = "documentation", "Documentation"

    code = models.CharField(max_length=80)
    objective_version = models.CharField(max_length=40, default="1.0")
    domain = models.CharField(max_length=80)
    objective = models.TextField(max_length=8000)
    control_type = models.CharField(max_length=20, choices=ControlType.choices)
    nature = models.CharField(max_length=20, choices=Nature.choices)
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "code", "objective_version"], name="uco_version_uniq")]


class FrameworkControlMapping(TenantScopedModel):
    class Coverage(models.TextChoices):
        FULL = "full", "Full"
        PARTIAL = "partial", "Partial"
        SUPPORTING = "supporting", "Supporting"
        NONE = "none", "None"

    class Source(models.TextChoices):
        EXPERT = "expert", "Expert"
        AI = "ai", "AI proposed"

    requirement = models.ForeignKey(Requirement, on_delete=models.PROTECT, related_name="control_mappings")
    unified_control = models.ForeignKey(
        UnifiedControlObjective, on_delete=models.PROTECT, related_name="framework_mappings"
    )
    coverage = models.CharField(max_length=20, choices=Coverage.choices)
    delta_condition = models.JSONField(default=dict, blank=True)
    rationale = models.TextField(blank=True, max_length=4000)
    confidence = models.DecimalField(max_digits=4, decimal_places=3, default=1)
    mapping_source = models.CharField(max_length=20, choices=Source.choices, default=Source.EXPERT)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "requirement", "unified_control"], name="framework_uco_mapping_uniq"
            )
        ]

    def clean(self):
        super().clean()
        if self.coverage == self.Coverage.PARTIAL:
            required = {"attribute", "operator", "value"}
            if not isinstance(self.delta_condition, dict) or not required <= set(self.delta_condition):
                raise ValidationError({"delta_condition": "Partial mappings require attribute, operator and value."})
        if self.mapping_source == self.Source.AI and not self.approved_by_id:
            raise ValidationError({"approved_by": "AI-proposed mappings require human approval."})


class EvidenceRequirement(TenantScopedModel):
    unified_control = models.ForeignKey(
        UnifiedControlObjective, on_delete=models.PROTECT, related_name="evidence_requirements"
    )
    artefact_type = models.CharField(max_length=80)
    required_attributes = models.JSONField(default=list)
    validity_period_days = models.PositiveIntegerField(null=True, blank=True)
    sampling_rule = models.JSONField(default=dict, blank=True)
    acceptance_criteria = models.JSONField(default=dict)


class OrganisationControl(TenantScopedModel):
    class Status(models.TextChoices):
        NOT_STARTED = "not_started", "Not started"
        EVIDENCE_SUBMITTED = "evidence_submitted", "Evidence submitted"
        UNDER_REVIEW = "under_review", "Under review"
        COMPLIANT = "compliant", "Compliant"
        PARTIAL = "partially_compliant", "Partially compliant"
        NONCOMPLIANT = "noncompliant", "Non-compliant"
        NOT_APPLICABLE = "not_applicable", "Not applicable"

    application = models.ForeignKey(Application, on_delete=models.PROTECT, related_name="organisation_controls")
    unified_control = models.ForeignKey(
        UnifiedControlObjective, on_delete=models.PROTECT, related_name="organisation_controls"
    )
    applicability = models.CharField(max_length=20, default="applicable")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)
    status = models.CharField(max_length=30, choices=Status.choices, default=Status.NOT_STARTED)
    implementation_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    maturity_level = models.DecimalField(max_digits=3, decimal_places=1, default=0)
    last_reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "application", "unified_control"], name="organisation_control_uniq"
            )
        ]


class ControlAssignment(TenantScopedModel):
    organisation_control = models.ForeignKey(OrganisationControl, on_delete=models.PROTECT, related_name="assignments")
    assignee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    evidence_scope = models.JSONField(default=list, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "organisation_control", "assignee"], name="control_assignment_uniq"
            )
        ]


class ControlEvidenceLink(ImmutableTenantRecord):
    organisation_control = models.ForeignKey(
        OrganisationControl, on_delete=models.PROTECT, related_name="evidence_links"
    )
    evidence = models.ForeignKey(
        "Evidence", on_delete=models.PROTECT, null=True, blank=True, related_name="control_links"
    )
    source_type = models.CharField(max_length=100)
    source_id = models.UUIDField()
    source_hash = models.CharField(max_length=64)
    verdict = models.CharField(max_length=30)
    confidence = models.PositiveSmallIntegerField(default=5)
    reason = models.TextField(max_length=4000)
    mapping_version = models.CharField(max_length=80)
    system_generated = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "organisation_control", "source_type", "source_id"],
                name="control_evidence_source_uniq",
            )
        ]


class Assessment(TenantScopedModel):
    application = models.ForeignKey(Application, on_delete=models.PROTECT)
    framework_version = models.ForeignKey(FrameworkVersion, on_delete=models.PROTECT)
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=30, default="draft")
    audit_period_start = models.DateField(null=True, blank=True)
    audit_period_end = models.DateField(null=True, blank=True)
    scope = models.JSONField(default=dict, blank=True)


class Evidence(TenantScopedModel):
    assessment = models.ForeignKey(Assessment, on_delete=models.PROTECT, related_name="evidence")
    title = models.CharField(max_length=300)
    source = models.CharField(max_length=600)
    evidence_date = models.DateField()
    object_key = models.CharField(max_length=600)
    sha256 = models.CharField(max_length=64)
    classification = models.CharField(max_length=80)
    media_type = models.CharField(max_length=100, default="application/octet-stream")
    extracted_attributes = models.JSONField(default=dict, blank=True)
    extraction_provenance = models.JSONField(default=dict, blank=True)
    extraction_confidence = models.DecimalField(max_digits=4, decimal_places=2, default=0)
    quality_score = models.DecimalField(max_digits=3, decimal_places=2, default=0)
    quality_breakdown = models.JSONField(default=dict, blank=True)
    quality_reasons = models.JSONField(default=list, blank=True)
    quality_suggestions = models.JSONField(default=list, blank=True)
    quality_threshold = models.DecimalField(max_digits=3, decimal_places=2, default=2.5)
    quality_passed = models.BooleanField(default=False)
    quality_profile_version = models.CharField(max_length=80, default="evidence-quality-1.0")
    immutable = models.BooleanField(default=True)
    evidence_version = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=20, default="current")
    supersedes = models.ForeignKey(
        "self", on_delete=models.PROTECT, null=True, blank=True, related_name="superseded_by"
    )
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="submitted_evidence"
    )

    class Meta:
        base_manager_name = "all_objects"
        constraints = [
            models.UniqueConstraint(
                fields=["supersedes"],
                condition=models.Q(supersedes__isnull=False),
                name="evidence_single_successor_uniq",
            )
        ]

    def clean(self):
        super().clean()
        if not self.supersedes_id:
            if self.evidence_version != 1:
                raise ValidationError({"evidence_version": "Initial evidence must be version 1."})
            return
        previous = Evidence.all_objects.filter(pk=self.supersedes_id).first()
        if not previous:
            raise ValidationError({"supersedes": "The superseded evidence does not exist."})
        if previous.assessment_id != self.assessment_id:
            raise ValidationError({"assessment": "A successor must remain in the same assessment."})
        if self.evidence_version != previous.evidence_version + 1:
            raise ValidationError({"evidence_version": "A successor must use the next evidence version."})
        if self.object_key == previous.object_key:
            raise ValidationError({"object_key": "A successor must use a new immutable object key."})

    def save(self, *args, **kwargs):
        if self.pk and Evidence.all_objects.filter(pk=self.pk).exists():
            raise ValidationError("Evidence is immutable; create a superseding version.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Evidence is immutable.")


class EvidenceReuseEvaluation(ImmutableTenantRecord):
    class Outcome(models.TextChoices):
        ACCEPT = "accept", "Accept"
        ACCEPT_REVIEW_SUGGESTED = "accept_review_suggested", "Accept, review suggested"
        PARTIAL = "partial", "Partial"
        REJECT_STALE = "reject_stale", "Reject: stale"
        REJECT_OUT_OF_SCOPE = "reject_out_of_scope", "Reject: out of scope"
        REJECT_INSUFFICIENT = "reject_insufficient", "Reject: insufficient"
        REJECT_LOW_QUALITY = "reject_low_quality", "Reject: low quality"
        DUPLICATE = "duplicate", "Duplicate"

    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT, related_name="reuse_evaluations")
    organisation_control = models.ForeignKey(
        OrganisationControl, on_delete=models.PROTECT, related_name="reuse_evaluations"
    )
    requirement = models.ForeignKey(Requirement, on_delete=models.PROTECT, related_name="reuse_evaluations")
    unified_control = models.ForeignKey(
        UnifiedControlObjective, on_delete=models.PROTECT, related_name="reuse_evaluations"
    )
    mapping = models.ForeignKey(FrameworkControlMapping, on_delete=models.PROTECT)
    mapping_coverage = models.CharField(max_length=20, choices=FrameworkControlMapping.Coverage.choices)
    outcome = models.CharField(max_length=40, choices=Outcome.choices)
    checks = models.JSONField(default=list, blank=True)
    reasons = models.JSONField(default=list, blank=True)
    engine_version = models.CharField(max_length=40, default="deterministic-reuse-1.0")
    confidence = models.DecimalField(max_digits=4, decimal_places=3, default=1)


class EvidenceQualityOverride(ImmutableTenantRecord):
    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT, related_name="quality_overrides")
    justification = models.TextField(max_length=4000)
    original_score = models.DecimalField(max_digits=3, decimal_places=2)
    configured_threshold = models.DecimalField(max_digits=3, decimal_places=2)
    authorized_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    authorized_at = models.DateTimeField(default=timezone.now)

    def clean(self):
        super().clean()
        if not self.justification.strip():
            raise ValidationError({"justification": "A quality override justification is required."})


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

    def clean(self):
        super().clean()
        if self.decision == self.Decision.NOT_APPLICABLE and not self.rationale.strip():
            raise ValidationError({"rationale": "Not-applicable conclusions require justification."})


class AssessmentEvidence(TenantScopedModel):
    response = models.ForeignKey(AssessmentResponse, on_delete=models.PROTECT)
    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "response", "evidence"], name="assessment_evidence_uniq")
        ]


class ComplianceGap(TenantScopedModel):
    response = models.ForeignKey(AssessmentResponse, on_delete=models.PROTECT, null=True, blank=True)
    organisation_control = models.ForeignKey(
        OrganisationControl, on_delete=models.PROTECT, null=True, blank=True, related_name="gaps"
    )
    description = models.TextField(max_length=8000)
    corrective_action = models.TextField(max_length=8000)
    status = models.CharField(max_length=30, default="open")
    source_fingerprint = models.CharField(max_length=64, blank=True)
    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT, null=True, blank=True, related_name="gaps")
    requirement = models.ForeignKey(Requirement, on_delete=models.PROTECT, null=True, blank=True)
    failed_check = models.CharField(max_length=80, blank=True)
    details = models.JSONField(default=dict, blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "source_fingerprint"],
                condition=models.Q(source_fingerprint__gt=""),
                name="compliance_gap_fingerprint_uniq",
            )
        ]


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

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "relationship", "source_type", "source_id"], name="risk_link_source_uniq"
            )
        ]


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
    gap = models.ForeignKey(ComplianceGap, on_delete=models.PROTECT, null=True, blank=True, related_name="remediations")
    description = models.TextField(max_length=8000)
    status = models.CharField(max_length=30, default="planned")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)


class Task(TenantScopedModel):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        IN_PROGRESS = "in_progress", "In progress"
        REVIEW = "review", "Review"
        COMPLETED = "completed", "Completed"

    task_type = models.CharField(max_length=60)
    title = models.CharField(max_length=300)
    description = models.TextField(max_length=8000)
    priority = models.CharField(max_length=20, default="medium")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)
    organisation_control = models.ForeignKey(
        OrganisationControl, on_delete=models.PROTECT, null=True, blank=True, related_name="tasks"
    )
    gap = models.ForeignKey(ComplianceGap, on_delete=models.PROTECT, null=True, blank=True, related_name="tasks")
    risk = models.ForeignKey(Risk, on_delete=models.PROTECT, null=True, blank=True, related_name="tasks")
    source_type = models.CharField(max_length=100, blank=True)
    source_id = models.UUIDField(null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "task_type", "source_type", "source_id"],
                condition=models.Q(source_id__isnull=False),
                name="task_source_uniq",
            )
        ]


class AssessmentObservation(ImmutableTenantRecord):
    assessment = models.ForeignKey(
        Assessment, on_delete=models.PROTECT, null=True, blank=True, related_name="observations"
    )
    organisation_control = models.ForeignKey(OrganisationControl, on_delete=models.PROTECT, related_name="observations")
    source_type = models.CharField(max_length=100)
    source_id = models.UUIDField()
    title = models.CharField(max_length=300)
    description = models.TextField(max_length=8000)
    outcome = models.CharField(max_length=30)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "source_type", "source_id"], name="observation_source_uniq")
        ]


class AuditorVerdict(ImmutableTenantRecord):
    class Decision(models.TextChoices):
        COMPLIANT = "compliant", "Compliant"
        PARTIAL = "partially_compliant", "Partially compliant"
        NONCOMPLIANT = "noncompliant", "Non-compliant"
        NOT_APPLICABLE = "not_applicable", "Not applicable"
        QUERY_RAISED = "query_raised", "Query raised"

    # Engagement belongs to the audit-firm tenant while this immutable verdict
    # belongs to the auditee. A UUID is intentional: the cross-tenant reference
    # is validated at the access boundary rather than pretending it is a normal
    # same-tenant foreign key.
    engagement_id = models.UUIDField()
    organisation_control = models.ForeignKey(
        OrganisationControl, on_delete=models.PROTECT, related_name="auditor_verdicts"
    )
    decision = models.CharField(max_length=30, choices=Decision.choices)
    rationale = models.TextField(max_length=8000)
    evidence_result_id = models.UUIDField(null=True, blank=True)
    finalized_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    finalized_at = models.DateTimeField(default=timezone.now)
    locked = models.BooleanField(default=True)
    supersedes = models.ForeignKey(
        "self", on_delete=models.PROTECT, null=True, blank=True, related_name="superseded_by"
    )

    class Meta:
        indexes = [models.Index(fields=["tenant", "engagement_id", "organisation_control"], name="verdict_scope_idx")]

    def clean(self):
        # Skip TenantScopedModel's generic relationship check only for the
        # intentionally cross-tenant engagement UUID; every actual FK here is
        # still tenant-owned and must match.
        TenantScopedModel.clean(self)
        if self.decision == self.Decision.NOT_APPLICABLE and not self.rationale.strip():
            raise ValidationError({"rationale": "Not-applicable verdicts require justification."})


class PostClosureEvidenceChange(ImmutableTenantRecord):
    organisation_control = models.ForeignKey(
        OrganisationControl, on_delete=models.PROTECT, related_name="post_closure_evidence_changes"
    )
    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT, related_name="post_closure_changes")
    prior_verdict = models.ForeignKey(AuditorVerdict, on_delete=models.PROTECT)
    evaluation = models.ForeignKey(EvidenceReuseEvaluation, on_delete=models.PROTECT)
    status = models.CharField(max_length=20, default="pending")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "organisation_control", "evidence", "prior_verdict"],
                name="post_closure_evidence_change_uniq",
            )
        ]


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
