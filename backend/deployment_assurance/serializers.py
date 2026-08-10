"""Serializers for the Deployment Assurance API.

Reuses ``core.serializers.TenantModelSerializer`` so that related-object
querysets are tenant-filtered and cross-tenant references are rejected before
they reach the database constraint. Fields that the engine owns — hashes,
scores, verdicts, state — are read-only everywhere: a client may describe what
it wants evaluated, never what the outcome was.
"""

from rest_framework import serializers

from core.serializers import TenantModelSerializer
from core.tenancy import current_tenant_id

from .models import (
    ControlMapping,
    ControlResult,
    DecisionThresholdProfile,
    DeploymentDecision,
    DeploymentSnapshot,
    DeploymentTarget,
    DriftEvent,
    EvaluationRun,
    EvidenceArtifact,
    ExceptionWaiver,
    PolicyPack,
    PolicyProfile,
    PolicyRule,
    SourceType,
)

BASE_READ_ONLY = ("tenant", "version", "created_at", "updated_at")


class TenantScopedFieldsMixin:
    """Bind related-field querysets to the active tenant.

    ``TenantModelSerializer`` does this for model serializers. Plain
    ``Serializer`` subclasses need it too: a ``PrimaryKeyRelatedField`` built
    from ``Model.objects.all()`` captures its queryset at class-definition time,
    when no tenant context exists — which resolves to an empty set and makes
    every lookup fail. Rebinding per request also means a primary key belonging
    to another tenant is reported as an invalid choice rather than leaking the
    fact that the object exists.
    """

    def get_fields(self):
        fields = super().get_fields()
        tenant_id = current_tenant_id()
        if not tenant_id:
            return fields
        for field in fields.values():
            related = field.child_relation if isinstance(field, serializers.ManyRelatedField) else field
            model = getattr(getattr(related, "queryset", None), "model", None)
            if model is not None and hasattr(model, "all_objects"):
                related.queryset = model.all_objects.filter(tenant_id=tenant_id)
        return fields


def _serializer(model, *, read_only_fields=(), fields="__all__"):
    meta = type(
        "Meta",
        (),
        {"model": model, "fields": fields, "read_only_fields": (*BASE_READ_ONLY, *read_only_fields)},
    )
    return type(f"{model.__name__}Serializer", (TenantModelSerializer,), {"Meta": meta})


DeploymentTargetSerializer = _serializer(
    DeploymentTarget, read_only_fields=("last_observed_at", "baseline_snapshot_id")
)
DecisionThresholdProfileSerializer = _serializer(DecisionThresholdProfile)
PolicyProfileSerializer = _serializer(PolicyProfile)
PolicyPackSerializer = _serializer(PolicyPack, read_only_fields=tuple(field.name for field in PolicyPack._meta.fields))
PolicyRuleSerializer = _serializer(PolicyRule, read_only_fields=tuple(field.name for field in PolicyRule._meta.fields))
ControlMappingSerializer = _serializer(
    ControlMapping, read_only_fields=tuple(field.name for field in ControlMapping._meta.fields)
)
ControlResultSerializer = _serializer(
    ControlResult, read_only_fields=tuple(field.name for field in ControlResult._meta.fields)
)
DeploymentDecisionSerializer = _serializer(
    DeploymentDecision, read_only_fields=tuple(field.name for field in DeploymentDecision._meta.fields)
)
EvidenceArtifactSerializer = _serializer(
    EvidenceArtifact, read_only_fields=tuple(field.name for field in EvidenceArtifact._meta.fields)
)
DriftEventSerializer = _serializer(DriftEvent, read_only_fields=("risk_delta", "detected_at"))


class DeploymentSnapshotSerializer(TenantModelSerializer):
    """Read representation of a stored snapshot. Creation uses the upload form."""

    class Meta:
        model = DeploymentSnapshot
        fields = "__all__"
        read_only_fields = tuple(field.name for field in DeploymentSnapshot._meta.fields)


class SnapshotUploadSerializer(TenantScopedFieldsMixin, serializers.Serializer):
    """Bounded multipart submission of a deployment artifact.

    The report's presigned-upload path is the scaling answer for large
    artifacts; this direct form is what a CI job actually needs for a plan of a
    few megabytes, and it keeps the ingest hash server-computed.
    """

    target = serializers.PrimaryKeyRelatedField(queryset=DeploymentTarget.objects.all())
    source_type = serializers.ChoiceField(choices=SourceType.choices)
    artifact = serializers.FileField()
    source_reference = serializers.CharField(required=False, allow_blank=True, max_length=400)
    source_revision = serializers.CharField(required=False, allow_blank=True, max_length=120)
    metadata = serializers.JSONField(required=False, default=dict)

    def validate_metadata(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("metadata must be an object.")
        return value


class EvaluationRequestSerializer(TenantScopedFieldsMixin, serializers.Serializer):
    """Request an evaluation of an already-finalized snapshot."""

    policy_profile = serializers.PrimaryKeyRelatedField(
        queryset=PolicyProfile.objects.all(), required=False, allow_null=True
    )
    trigger = serializers.ChoiceField(choices=EvaluationRun.Trigger.choices, default=EvaluationRun.Trigger.MANUAL)
    context = serializers.JSONField(required=False, default=dict)
    parameters = serializers.JSONField(required=False, default=dict)

    def validate_parameters(self, value):
        """Per-run overrides are ``{rule_id: {parameter: value}}``."""
        if not isinstance(value, dict):
            raise serializers.ValidationError("parameters must be an object keyed by rule id.")
        for rule_id, overrides in value.items():
            if not isinstance(overrides, dict):
                raise serializers.ValidationError(f"Overrides for {rule_id!r} must be an object.")
        return value

    def validate_context(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("context must be an object.")
        return value


class EvaluationRunSerializer(TenantModelSerializer):
    class Meta:
        model = EvaluationRun
        fields = "__all__"
        read_only_fields = tuple(field.name for field in EvaluationRun._meta.fields)


class ExceptionWaiverSerializer(TenantModelSerializer):
    class Meta:
        model = ExceptionWaiver
        fields = "__all__"
        read_only_fields = (
            *BASE_READ_ONLY,
            "status",
            "requested_by",
            "approved_by",
            "decided_at",
            "decision_reason",
        )

    def validate_compensating_controls(self, value):
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise serializers.ValidationError("compensating_controls must be a list of strings.")
        return value


class WaiverDecisionSerializer(serializers.Serializer):
    decision = serializers.ChoiceField(choices=["approved", "rejected"])
    reason = serializers.CharField(max_length=4000)


SERIALIZERS = {
    DeploymentTarget: DeploymentTargetSerializer,
    DeploymentSnapshot: DeploymentSnapshotSerializer,
    EvaluationRun: EvaluationRunSerializer,
    ControlResult: ControlResultSerializer,
    DeploymentDecision: DeploymentDecisionSerializer,
    EvidenceArtifact: EvidenceArtifactSerializer,
    ExceptionWaiver: ExceptionWaiverSerializer,
    DriftEvent: DriftEventSerializer,
    PolicyPack: PolicyPackSerializer,
    PolicyRule: PolicyRuleSerializer,
    PolicyProfile: PolicyProfileSerializer,
    ControlMapping: ControlMappingSerializer,
    DecisionThresholdProfile: DecisionThresholdProfileSerializer,
}
