"""Deployment Assurance domain model.

The module governs two things with one schema: a *proposed* deployment (an
infrastructure-as-code artifact evaluated before merge) and an *observed*
deployment (live state collected from a provider). Both become a
``DeploymentSnapshot`` over the same canonical resource envelope, so a rule
written once applies to both.

Every tenant-owned model here extends ``core.models.TenantScopedModel`` and is
registered in the accompanying row-level-security migration. Application-level
filtering is a convenience; the database is the enforcement boundary.
"""

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

from core.models import Application, ComplianceGap, Risk, TenantScopedModel, UnifiedControlObjective

SHA256_LENGTH = 64


class Provider(models.TextChoices):
    AWS = "aws", "Amazon Web Services"
    AZURE = "azure", "Microsoft Azure"
    GCP = "gcp", "Google Cloud"
    KUBERNETES = "kubernetes", "Kubernetes"
    VMWARE = "vmware", "VMware"
    ON_PREM = "on_prem", "On-premises"
    GENERIC = "generic", "Provider-neutral"


class Environment(models.TextChoices):
    DEVELOPMENT = "development", "Development"
    TEST = "test", "Test"
    STAGING = "staging", "Staging"
    PRODUCTION = "production", "Production"


class SourceType(models.TextChoices):
    TERRAFORM_PLAN = "terraform_plan", "Terraform plan JSON"
    KUBERNETES_MANIFEST = "kubernetes_manifest", "Kubernetes manifest YAML"
    COMPOSE_FILE = "compose_file", "Docker Compose YAML"
    SERVER_INVENTORY = "server_inventory", "Normalized server inventory JSON"
    CLOUD_INVENTORY = "cloud_inventory", "Provider inventory collection"


class Outcome(models.TextChoices):
    PASS = "pass", "Pass"
    FAIL = "fail", "Fail"
    WARNING = "warning", "Warning"
    NOT_APPLICABLE = "not_applicable", "Not applicable"
    NOT_EVALUATED = "not_evaluated", "Not evaluated"
    ERROR = "error", "Error"
    MANUAL_REVIEW = "manual_review", "Manual review"


class Decision(models.TextChoices):
    APPROVED = "approved", "Approved"
    APPROVED_WITH_ACTIONS = "approved_with_actions", "Approved with actions"
    MANUAL_REVIEW = "manual_review", "Manual review"
    BLOCKED = "blocked", "Blocked"
    ERROR = "error", "Evaluation error"


class AutomationClass(models.TextChoices):
    GUIDANCE = "guidance", "Guidance only"
    PATCH = "patch", "Patch generation"
    APPROVAL_REQUIRED = "approval_required", "Approval-required execution"
    AUTONOMOUS_SAFE = "autonomous_safe", "Autonomous safe"


class DecisionThresholdProfile(TenantScopedModel):
    """Versioned thresholds that turn results into a gate decision.

    Immutable once referenced by a decision; tailoring produces a new version so
    that a historical decision can always be recomputed from its exact profile.
    """

    name = models.CharField(max_length=120)
    profile_version = models.CharField(max_length=40, default="1.0.0")
    block_at_risk = models.DecimalField(max_digits=5, decimal_places=2, default=70)
    manual_review_at_risk = models.DecimalField(max_digits=5, decimal_places=2, default=50)
    actions_at_risk = models.DecimalField(max_digits=5, decimal_places=2, default=25)
    block_critical_on_production = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)

    class Meta:
        db_table = "da_threshold_profile"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "name", "profile_version"], name="da_threshold_profile_uniq")
        ]

    def clean(self):
        super().clean()
        if not (self.actions_at_risk <= self.manual_review_at_risk <= self.block_at_risk):
            raise ValidationError({"manual_review_at_risk": "Thresholds must ascend: actions <= review <= block."})


class PolicyPack(TenantScopedModel):
    """An immutable, content-addressed collection of policy rules.

    ``content_hash`` covers every rule definition in the pack. An evaluation
    records the hash it ran against, so a result stays reproducible even after
    the pack is superseded.
    """

    key = models.CharField(max_length=80)
    pack_version = models.CharField(max_length=40)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=4000)
    content_hash = models.CharField(max_length=SHA256_LENGTH)
    signing_identity = models.CharField(max_length=200, blank=True)
    engine_version = models.CharField(max_length=40)
    approved_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "da_policy_pack"
        constraints = [models.UniqueConstraint(fields=["tenant", "key", "pack_version"], name="da_policy_pack_uniq")]

    def __str__(self):
        return f"{self.key}@{self.pack_version}"


class PolicyRule(TenantScopedModel):
    """One machine-testable technical assertion.

    ``entrypoint`` names a rule registered in the built-in Python registry.
    Arbitrary source is never accepted over the API; adding a rule is a release
    activity, not a runtime one.
    """

    class Category(models.TextChoices):
        NETWORK = "network", "Network"
        IDENTITY = "identity", "Identity"
        ENCRYPTION = "encryption", "Encryption"
        LOGGING = "logging", "Logging"
        BACKUP = "backup", "Backup"
        VULNERABILITY = "vulnerability", "Vulnerability"
        CONFIGURATION = "configuration", "Configuration"
        SUPPLY_CHAIN = "supply_chain", "Supply chain"

    policy_pack = models.ForeignKey(PolicyPack, on_delete=models.PROTECT, related_name="rules")
    unified_control = models.ForeignKey(
        UnifiedControlObjective, on_delete=models.PROTECT, null=True, blank=True, related_name="deployment_rules"
    )
    stable_key = models.CharField(max_length=40)
    rule_version = models.CharField(max_length=40)
    title = models.CharField(max_length=200)
    description = models.TextField(max_length=4000)
    category = models.CharField(max_length=20, choices=Category.choices)
    severity = models.PositiveSmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(5)])
    entrypoint = models.CharField(max_length=200)
    resource_types = models.JSONField(default=list)
    parameters = models.JSONField(default=dict, blank=True)
    remediation_guidance = models.TextField(max_length=4000)
    automation_class = models.CharField(
        max_length=30, choices=AutomationClass.choices, default=AutomationClass.GUIDANCE
    )
    blocking = models.BooleanField(default=False)
    content_hash = models.CharField(max_length=SHA256_LENGTH)
    active = models.BooleanField(default=True)

    class Meta:
        db_table = "da_policy_rule"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "policy_pack", "stable_key"], name="da_policy_rule_uniq")
        ]

    def __str__(self):
        return f"{self.stable_key}@{self.rule_version}"


class ControlMapping(TenantScopedModel):
    """Traceability from a technical rule to a published framework control.

    This records that a rule *contributes evidence toward* a control. It is not
    an assertion of certification; a human assessor still owns that conclusion.
    """

    policy_rule = models.ForeignKey(PolicyRule, on_delete=models.PROTECT, related_name="mappings")
    framework = models.CharField(max_length=80)
    framework_version = models.CharField(max_length=40)
    control_id = models.CharField(max_length=80)
    note = models.CharField(max_length=400, blank=True)

    class Meta:
        db_table = "da_control_mapping"
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "policy_rule", "framework", "framework_version", "control_id"],
                name="da_control_mapping_uniq",
            )
        ]


class PolicyProfile(TenantScopedModel):
    """Tenant tailoring of a pack: which rules apply and with what parameters."""

    policy_pack = models.ForeignKey(PolicyPack, on_delete=models.PROTECT, related_name="profiles")
    threshold_profile = models.ForeignKey(DecisionThresholdProfile, on_delete=models.PROTECT)
    name = models.CharField(max_length=120)
    excluded_rule_keys = models.JSONField(default=list, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    is_default = models.BooleanField(default=False)

    class Meta:
        db_table = "da_policy_profile"
        constraints = [models.UniqueConstraint(fields=["tenant", "name"], name="da_policy_profile_uniq")]


class DeploymentTarget(TenantScopedModel):
    """The stable thing being governed, independent of any single observation."""

    class TargetType(models.TextChoices):
        ACCOUNT = "account", "Cloud account"
        SUBSCRIPTION = "subscription", "Subscription"
        PROJECT = "project", "Project"
        CLUSTER = "cluster", "Cluster"
        SERVER = "server", "Server"
        SERVER_GROUP = "server_group", "Server group"
        APPLICATION_STACK = "application_stack", "Application stack"
        IAC_DEPLOYMENT = "iac_deployment", "IaC deployment"

    class State(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        DECOMMISSIONING = "decommissioning", "Decommissioning"
        DECOMMISSIONED = "decommissioned", "Decommissioned"

    application = models.ForeignKey(Application, on_delete=models.PROTECT, related_name="deployment_targets")
    policy_profile = models.ForeignKey(PolicyProfile, on_delete=models.PROTECT, null=True, blank=True)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=120)
    provider = models.CharField(max_length=20, choices=Provider.choices)
    target_type = models.CharField(max_length=30, choices=TargetType.choices)
    environment = models.CharField(max_length=20, choices=Environment.choices)
    external_id = models.CharField(max_length=400)
    region = models.CharField(max_length=80, blank=True)
    criticality = models.PositiveSmallIntegerField(default=3, validators=[MinValueValidator(0), MaxValueValidator(5)])
    data_sensitivity = models.PositiveSmallIntegerField(
        default=3, validators=[MinValueValidator(0), MaxValueValidator(5)]
    )
    internet_exposed = models.BooleanField(default=False)
    owner_reference = models.CharField(max_length=200, blank=True)
    labels = models.JSONField(default=dict, blank=True)
    state = models.CharField(max_length=20, choices=State.choices, default=State.ACTIVE)
    baseline_snapshot_id = models.UUIDField(null=True, blank=True)
    last_observed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "da_deployment_target"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "provider", "external_id"], name="da_target_external_uniq"),
            models.UniqueConstraint(fields=["tenant", "application", "slug"], name="da_target_slug_uniq"),
        ]

    def __str__(self):
        return self.name

    @property
    def is_protected(self) -> bool:
        """Production or internet-exposed targets fail closed on evaluation error."""
        return self.environment == Environment.PRODUCTION or self.internet_exposed


class DeploymentSnapshot(TenantScopedModel):
    """An immutable proposed or observed state of a target.

    The original artifact and the canonical normalized form are stored
    separately and hashed separately. Re-normalizing under a newer parser
    therefore produces new evidence without destroying the source of record.
    """

    class IngestionState(models.TextChoices):
        UPLOADING = "uploading", "Uploading"
        VALIDATING = "validating", "Validating"
        READY = "ready", "Ready"
        REJECTED = "rejected", "Rejected"

    class CollectorType(models.TextChoices):
        USER = "user", "User"
        SERVICE_ACCOUNT = "service_account", "Service account"
        CONNECTOR = "connector", "Connector"
        SYSTEM = "system", "System"

    target = models.ForeignKey(DeploymentTarget, on_delete=models.PROTECT, related_name="snapshots")
    source_type = models.CharField(max_length=30, choices=SourceType.choices)
    source_reference = models.CharField(max_length=400, blank=True)
    source_revision = models.CharField(max_length=120, blank=True)
    artifact_object_key = models.CharField(max_length=600)
    artifact_sha256 = models.CharField(max_length=SHA256_LENGTH)
    artifact_size = models.PositiveBigIntegerField()
    media_type = models.CharField(max_length=120, default="application/octet-stream")
    schema_version = models.CharField(max_length=60, default="trishul-snapshot/1.0")
    normalized_object_key = models.CharField(max_length=600, blank=True)
    normalized_sha256 = models.CharField(max_length=SHA256_LENGTH, blank=True)
    resource_count = models.PositiveIntegerField(default=0)
    collected_at = models.DateTimeField(default=timezone.now)
    collected_by_type = models.CharField(max_length=20, choices=CollectorType.choices)
    collected_by_id = models.CharField(max_length=200, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    supersedes = models.ForeignKey(
        "self", on_delete=models.PROTECT, null=True, blank=True, related_name="superseded_by"
    )
    ingestion_state = models.CharField(max_length=20, choices=IngestionState.choices, default=IngestionState.UPLOADING)
    finalized_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "da_deployment_snapshot"
        indexes = [models.Index(fields=["tenant", "target", "-created_at"], name="da_snapshot_target_idx")]

    @property
    def is_ready(self) -> bool:
        return self.ingestion_state == self.IngestionState.READY


class EvaluationRun(TenantScopedModel):
    """One reproducible execution of a policy pack against a snapshot.

    ``input_hash``, ``policy_hash`` and ``engine_versions`` together determine
    the output. Re-running an identical triple must produce byte-equivalent
    result content.
    """

    class Trigger(models.TextChoices):
        PULL_REQUEST = "pull_request", "Pull request"
        PRE_DEPLOY = "pre_deploy", "Pre-deployment"
        POST_DEPLOY = "post_deploy", "Post-deployment"
        SCHEDULED = "scheduled", "Scheduled"
        DRIFT = "drift", "Drift check"
        MANUAL = "manual", "Manual"

    class State(models.TextChoices):
        QUEUED = "queued", "Queued"
        NORMALIZING = "normalizing", "Normalizing"
        EVALUATING = "evaluating", "Evaluating"
        DECIDING = "deciding", "Deciding"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    TERMINAL_STATES = frozenset({State.COMPLETED, State.FAILED, State.CANCELLED})

    snapshot = models.ForeignKey(DeploymentSnapshot, on_delete=models.PROTECT, related_name="evaluations")
    target = models.ForeignKey(DeploymentTarget, on_delete=models.PROTECT, related_name="evaluations")
    policy_pack = models.ForeignKey(PolicyPack, on_delete=models.PROTECT)
    policy_profile = models.ForeignKey(PolicyProfile, on_delete=models.PROTECT, null=True, blank=True)
    trigger = models.CharField(max_length=20, choices=Trigger.choices, default=Trigger.MANUAL)
    state = models.CharField(max_length=20, choices=State.choices, default=State.QUEUED)
    idempotency_key = models.CharField(max_length=200, blank=True)
    correlation_id = models.UUIDField(default=uuid.uuid4)
    requested_by_type = models.CharField(max_length=20, choices=DeploymentSnapshot.CollectorType.choices)
    requested_by_id = models.CharField(max_length=200, blank=True)
    input_hash = models.CharField(max_length=SHA256_LENGTH, blank=True)
    policy_hash = models.CharField(max_length=SHA256_LENGTH, blank=True)
    engine_versions = models.JSONField(default=dict, blank=True)
    context = models.JSONField(default=dict, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    result_manifest_key = models.CharField(max_length=600, blank=True)
    result_manifest_hash = models.CharField(max_length=SHA256_LENGTH, blank=True)
    error_code = models.CharField(max_length=80, blank=True)
    summary = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "da_evaluation_run"
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "idempotency_key"],
                condition=models.Q(idempotency_key__gt=""),
                name="da_evaluation_idempotency_uniq",
            )
        ]
        indexes = [models.Index(fields=["tenant", "target", "-created_at"], name="da_evaluation_target_idx")]


class ControlResult(TenantScopedModel):
    """A single rule outcome for a single resource.

    ``fingerprint`` is stable across runs for the same rule/resource/reason, so
    a finding can be tracked, waived and closed across evaluations.
    """

    evaluation_run = models.ForeignKey(EvaluationRun, on_delete=models.PROTECT, related_name="results")
    policy_rule = models.ForeignKey(PolicyRule, on_delete=models.PROTECT, related_name="results")
    resource_type = models.CharField(max_length=80)
    resource_id = models.CharField(max_length=400)
    resource_path = models.CharField(max_length=600, blank=True)
    outcome = models.CharField(max_length=20, choices=Outcome.choices)
    reason_code = models.CharField(max_length=80)
    severity = models.PositiveSmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(5)])
    confidence = models.PositiveSmallIntegerField(default=4, validators=[MinValueValidator(0), MaxValueValidator(5)])
    rationale = models.TextField(max_length=4000)
    expected = models.JSONField(default=dict, blank=True)
    observed = models.JSONField(default=dict, blank=True)
    fingerprint = models.CharField(max_length=SHA256_LENGTH)
    blocking = models.BooleanField(default=False)
    waived_by = models.ForeignKey(
        "ExceptionWaiver", on_delete=models.PROTECT, null=True, blank=True, related_name="results"
    )
    risk = models.ForeignKey(Risk, on_delete=models.PROTECT, null=True, blank=True, related_name="deployment_results")
    gap = models.ForeignKey(
        ComplianceGap, on_delete=models.PROTECT, null=True, blank=True, related_name="deployment_results"
    )
    residual_risk = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    class Meta:
        db_table = "da_control_result"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "evaluation_run", "fingerprint"], name="da_control_result_uniq")
        ]
        indexes = [models.Index(fields=["tenant", "evaluation_run", "outcome"], name="da_result_outcome_idx")]

    @property
    def is_open_failure(self) -> bool:
        return self.outcome == Outcome.FAIL and self.waived_by_id is None


class EvidenceArtifact(TenantScopedModel):
    """Immutable evidence metadata pointing at an object-store artifact."""

    class Role(models.TextChoices):
        SOURCE_ARTIFACT = "source_artifact", "Source artifact"
        NORMALIZED_SNAPSHOT = "normalized_snapshot", "Normalized snapshot"
        RESULT_MANIFEST = "result_manifest", "Result manifest"
        DECISION_ENVELOPE = "decision_envelope", "Decision envelope"

    target = models.ForeignKey(DeploymentTarget, on_delete=models.PROTECT, related_name="evidence")
    snapshot = models.ForeignKey(
        DeploymentSnapshot, on_delete=models.PROTECT, null=True, blank=True, related_name="evidence"
    )
    evaluation_run = models.ForeignKey(
        EvaluationRun, on_delete=models.PROTECT, null=True, blank=True, related_name="evidence"
    )
    role = models.CharField(max_length=30, choices=Role.choices)
    object_key = models.CharField(max_length=600)
    media_type = models.CharField(max_length=120, default="application/json")
    size_bytes = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=SHA256_LENGTH)
    envelope = models.JSONField(default=dict)
    classification = models.CharField(max_length=40, default="confidential")
    retention_class = models.CharField(max_length=60, default="deployment-evidence-default")
    legal_hold = models.BooleanField(default=False)

    class Meta:
        db_table = "da_evidence_artifact"
        constraints = [models.UniqueConstraint(fields=["tenant", "object_key"], name="da_evidence_object_key_uniq")]


class ExceptionWaiver(TenantScopedModel):
    """A scoped, time-bound, independently approved exception to one rule.

    A waiver is bound to a rule *version* and a resource fingerprint. Changing
    either invalidates it, which prevents a narrow approval from silently
    covering a broader or newer condition.
    """

    class Status(models.TextChoices):
        REQUESTED = "requested", "Requested"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        EXPIRED = "expired", "Expired"
        REVOKED = "revoked", "Revoked"

    target = models.ForeignKey(DeploymentTarget, on_delete=models.PROTECT, related_name="waivers")
    policy_rule = models.ForeignKey(PolicyRule, on_delete=models.PROTECT, related_name="waivers")
    rule_version = models.CharField(max_length=40)
    resource_fingerprint = models.CharField(max_length=SHA256_LENGTH)
    reason = models.TextField(max_length=4000)
    compensating_controls = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.REQUESTED)
    expires_at = models.DateTimeField()
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="deployment_waiver_requests"
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="deployment_waiver_approvals",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_reason = models.TextField(blank=True, max_length=4000)

    class Meta:
        db_table = "da_exception_waiver"
        indexes = [models.Index(fields=["tenant", "target", "status"], name="da_waiver_status_idx")]

    def clean(self):
        super().clean()
        if self.approved_by_id and self.approved_by_id == self.requested_by_id:
            raise ValidationError({"approved_by": "Requesters cannot approve their own waiver."})

    def covers(self, result: ControlResult, *, now=None) -> bool:
        """Whether this waiver suppresses the given result at evaluation time."""
        now = now or timezone.now()
        return (
            self.status == self.Status.APPROVED
            and self.expires_at > now
            and self.policy_rule_id == result.policy_rule_id
            and self.rule_version == result.policy_rule.rule_version
            and self.resource_fingerprint == result.fingerprint
        )


class DeploymentDecision(TenantScopedModel):
    """The immutable gate conclusion for one evaluation run.

    A completed decision is never updated in place. A later evaluation creates a
    new decision and links the previous one through ``superseded_by``.
    """

    evaluation_run = models.OneToOneField(EvaluationRun, on_delete=models.PROTECT, related_name="decision")
    target = models.ForeignKey(DeploymentTarget, on_delete=models.PROTECT, related_name="decisions")
    threshold_profile = models.ForeignKey(DecisionThresholdProfile, on_delete=models.PROTECT)
    decision = models.CharField(max_length=30, choices=Decision.choices)
    compliance_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    reason_codes = models.JSONField(default=list)
    counts = models.JSONField(default=dict)
    decision_hash = models.CharField(max_length=SHA256_LENGTH)
    finalized_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    superseded_by = models.ForeignKey(
        "self", on_delete=models.PROTECT, null=True, blank=True, related_name="supersedes"
    )

    class Meta:
        db_table = "da_deployment_decision"
        indexes = [models.Index(fields=["tenant", "target", "-created_at"], name="da_decision_target_idx")]

    @property
    def permits_deployment(self) -> bool:
        return self.decision in {Decision.APPROVED, Decision.APPROVED_WITH_ACTIONS}


class DriftEvent(TenantScopedModel):
    """Policy-relevant divergence between an approved baseline and live state.

    Ordinary metadata churn is intentionally *not* a drift event; only a change
    in control outcomes opens one.
    """

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ACKNOWLEDGED = "acknowledged", "Acknowledged"
        REMEDIATING = "remediating", "Remediating"
        RESOLVED = "resolved", "Resolved"
        ACCEPTED = "accepted", "Accepted"

    target = models.ForeignKey(DeploymentTarget, on_delete=models.PROTECT, related_name="drift_events")
    baseline_snapshot = models.ForeignKey(
        DeploymentSnapshot, on_delete=models.PROTECT, related_name="baseline_drift_events"
    )
    observed_snapshot = models.ForeignKey(
        DeploymentSnapshot, on_delete=models.PROTECT, related_name="observed_drift_events"
    )
    evaluation_run = models.ForeignKey(EvaluationRun, on_delete=models.PROTECT, related_name="drift_events")
    introduced_fingerprints = models.JSONField(default=list)
    resolved_fingerprints = models.JSONField(default=list)
    risk_delta = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    detected_at = models.DateTimeField(default=timezone.now)
    resolution = models.TextField(blank=True, max_length=4000)

    class Meta:
        db_table = "da_drift_event"
        indexes = [models.Index(fields=["tenant", "target", "status"], name="da_drift_status_idx")]
