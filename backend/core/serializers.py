from rest_framework import serializers

from .ai_gateway import validate_endpoint
from .models import (
    AIAnalysisRun,
    Application,
    Approval,
    ArchitectureComponent,
    Assessment,
    AssessmentEvidence,
    AssessmentObservation,
    AssessmentResponse,
    AuditEvent,
    AuditorVerdict,
    ComplianceGap,
    ControlAssignment,
    ControlEvidenceLink,
    DataFlow,
    Engagement,
    EngagementMember,
    EngagementScope,
    EngagementStatusHistory,
    Evidence,
    EvidenceRequirement,
    Finding,
    FindingEvidence,
    Framework,
    FrameworkControlMapping,
    FrameworkVersion,
    Job,
    Membership,
    ModelConfiguration,
    OrganisationControl,
    Organization,
    PromptVersion,
    Remediation,
    Report,
    Repository,
    RepositoryVersion,
    Requirement,
    Risk,
    RiskAcceptance,
    RiskLink,
    RiskScore,
    Scan,
    ServiceAccount,
    SubscriptionPlan,
    Task,
    Tenant,
    TenantBranding,
    TenantEntitlement,
    TenantInvitation,
    TenantRelationship,
    TenantScopedModel,
    TenantSubscription,
    Threat,
    ThreatModel,
    UnifiedControlObjective,
    UsageRecord,
    Workspace,
)
from .tenancy import current_tenant_id


class TenantModelSerializer(serializers.ModelSerializer):
    def get_fields(self):
        fields = super().get_fields()
        tenant_id = current_tenant_id()
        for field in fields.values():
            related = field.child_relation if isinstance(field, serializers.ManyRelatedField) else field
            queryset = getattr(related, "queryset", None)
            model = getattr(queryset, "model", None)
            if tenant_id and model and issubclass(model, TenantScopedModel):
                related.queryset = model.all_objects.filter(tenant_id=tenant_id)
        return fields

    def validate(self, attrs):
        attrs = super().validate(attrs)
        tenant_id = current_tenant_id()
        for name, value in attrs.items():
            if isinstance(value, TenantScopedModel) and value.tenant_id != tenant_id:
                raise serializers.ValidationError({name: "Cross-tenant relationships are forbidden."})
        return attrs


def serializer_for(model, *, read_only_fields=()):
    meta = type(
        "Meta",
        (),
        {
            "model": model,
            "fields": "__all__",
            "read_only_fields": ("tenant", "version", "created_at", "updated_at", *read_only_fields),
        },
    )
    return type(f"{model.__name__}Serializer", (TenantModelSerializer,), {"Meta": meta})


OrganizationSerializer = serializer_for(Organization)
WorkspaceSerializer = serializer_for(Workspace)
ApplicationSerializer = serializer_for(Application)
MembershipSerializer = serializer_for(Membership)
TenantRelationshipSerializer = serializer_for(TenantRelationship)
SubscriptionPlanSerializer = serializer_for(SubscriptionPlan)
TenantSubscriptionSerializer = serializer_for(TenantSubscription)
TenantEntitlementSerializer = serializer_for(TenantEntitlement)
UsageRecordSerializer = serializer_for(
    UsageRecord, read_only_fields=tuple(field.name for field in UsageRecord._meta.fields)
)
TenantBrandingSerializer = serializer_for(TenantBranding)
TenantInvitationSerializer = serializer_for(
    TenantInvitation, read_only_fields=("target_tenant", "invited_by", "accepted_at")
)
EngagementSerializer = serializer_for(Engagement, read_only_fields=("status", "created_by", "approved_by"))
EngagementScopeSerializer = serializer_for(EngagementScope)
EngagementMemberSerializer = serializer_for(EngagementMember)
EngagementStatusHistorySerializer = serializer_for(
    EngagementStatusHistory, read_only_fields=tuple(field.name for field in EngagementStatusHistory._meta.fields)
)
RepositorySerializer = serializer_for(Repository)
RepositoryVersionSerializer = serializer_for(RepositoryVersion, read_only_fields=("immutable",))
JobSerializer = serializer_for(Job)
ScanSerializer = serializer_for(Scan, read_only_fields=("state", "coverage"))
FindingSerializer = serializer_for(Finding)
FindingEvidenceSerializer = serializer_for(FindingEvidence)
ThreatModelSerializer = serializer_for(ThreatModel)
ArchitectureComponentSerializer = serializer_for(ArchitectureComponent)
DataFlowSerializer = serializer_for(DataFlow)
ThreatSerializer = serializer_for(Threat)
FrameworkVersionSerializer = serializer_for(FrameworkVersion)
RequirementSerializer = serializer_for(Requirement)
FrameworkSerializer = serializer_for(Framework)
UnifiedControlObjectiveSerializer = serializer_for(UnifiedControlObjective)
FrameworkControlMappingSerializer = serializer_for(FrameworkControlMapping)
EvidenceRequirementSerializer = serializer_for(EvidenceRequirement)
OrganisationControlSerializer = serializer_for(OrganisationControl, read_only_fields=("status", "last_reviewed_at"))
ControlAssignmentSerializer = serializer_for(ControlAssignment)
ControlEvidenceLinkSerializer = serializer_for(
    ControlEvidenceLink, read_only_fields=tuple(field.name for field in ControlEvidenceLink._meta.fields)
)
AssessmentSerializer = serializer_for(Assessment)
class EvidenceSerializer(TenantModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = Evidence
        fields = "__all__"
        read_only_fields = (
            "tenant",
            "version",
            "created_at",
            "updated_at",
            "immutable",
            "evidence_version",
            "status",
            "supersedes",
        )

    def get_status(self, obj):
        return "superseded" if obj.superseded_by.exists() else "current"

    def validate_object_key(self, value):
        if not value.startswith(f"{current_tenant_id()}/"):
            raise serializers.ValidationError("Evidence object keys must use the active tenant prefix.")
        return value


class EvidenceReplacementSerializer(TenantModelSerializer):
    class Meta:
        model = Evidence
        fields = ("title", "source", "evidence_date", "object_key", "sha256", "classification")

    def validate_object_key(self, value):
        if not value.startswith(f"{current_tenant_id()}/"):
            raise serializers.ValidationError("Evidence object keys must use the active tenant prefix.")
        return value


class EvidenceUploadSerializer(TenantModelSerializer):
    file = serializers.FileField(write_only=True)

    class Meta:
        model = Evidence
        fields = ("assessment", "title", "source", "evidence_date", "classification", "file")


class EvidenceReplacementUploadSerializer(EvidenceUploadSerializer):
    class Meta(EvidenceUploadSerializer.Meta):
        fields = ("title", "source", "evidence_date", "classification", "file")


ComplianceGapSerializer = serializer_for(ComplianceGap)
AssessmentEvidenceSerializer = serializer_for(AssessmentEvidence)
RiskSerializer = serializer_for(Risk)
RiskLinkSerializer = serializer_for(RiskLink)
RemediationSerializer = serializer_for(Remediation)
TaskSerializer = serializer_for(Task)
AssessmentObservationSerializer = serializer_for(
    AssessmentObservation, read_only_fields=tuple(field.name for field in AssessmentObservation._meta.fields)
)
AuditorVerdictSerializer = serializer_for(
    AuditorVerdict, read_only_fields=tuple(field.name for field in AuditorVerdict._meta.fields)
)
RiskAcceptanceSerializer = serializer_for(RiskAcceptance, read_only_fields=("status", "requested_by"))
ApprovalSerializer = serializer_for(Approval, read_only_fields=("approver",))
PromptVersionSerializer = serializer_for(PromptVersion)
AIAnalysisRunSerializer = serializer_for(
    AIAnalysisRun,
    read_only_fields=(
        "state",
        "request_hash",
        "response_hash",
        "input_tokens",
        "output_tokens",
        "policy_decisions",
        "error_code",
    ),
)
ReportSerializer = serializer_for(Report, read_only_fields=("content_hash", "source_versions", "generated_by"))


class AssessmentResponseSerializer(TenantModelSerializer):
    class Meta:
        model = AssessmentResponse
        fields = "__all__"
        read_only_fields = ("tenant", "version", "created_at", "updated_at", "reviewed_by")

    def validate(self, attrs):
        attrs = super().validate(attrs)
        decision = attrs.get("decision", getattr(self.instance, "decision", "unanswered"))
        evidence = attrs.get("evidence")
        has_existing = self.instance and self.instance.evidence.exists()
        if decision == AssessmentResponse.Decision.COMPLIANT and not evidence and not has_existing:
            raise serializers.ValidationError({"evidence": "A compliant conclusion requires evidence."})
        rationale = attrs.get("rationale", getattr(self.instance, "rationale", ""))
        if decision == AssessmentResponse.Decision.NOT_APPLICABLE and not rationale.strip():
            raise serializers.ValidationError({"rationale": "Not-applicable conclusions require justification."})
        return attrs


class RiskScoreSerializer(TenantModelSerializer):
    class Meta:
        model = RiskScore
        fields = "__all__"
        read_only_fields = tuple(field.name for field in RiskScore._meta.fields)


class ModelConfigurationSerializer(TenantModelSerializer):
    class Meta:
        model = ModelConfiguration
        fields = "__all__"
        read_only_fields = ("tenant", "version", "created_at", "updated_at")
        extra_kwargs = {"credential_reference": {"write_only": True}}

    def validate_endpoint_url(self, value):
        validate_endpoint(value)
        return value


class ServiceAccountSerializer(TenantModelSerializer):
    class Meta:
        model = ServiceAccount
        fields = ("id", "name", "scopes", "application_ids", "expires_at", "last_used_at", "revoked_at", "created_at")
        read_only_fields = ("id", "last_used_at", "revoked_at", "created_at")


class TenantSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = (
            "id",
            "slug",
            "name",
            "tenant_type",
            "auditee_mode",
            "isolation_tier",
            "is_active",
            "retention_days",
            "created_at",
        )
        read_only_fields = fields


class AuditFirmOnboardingSerializer(serializers.Serializer):
    slug = serializers.SlugField(max_length=80)
    name = serializers.CharField(max_length=200)
    administrator_email = serializers.EmailField()
    plan_key = serializers.CharField(max_length=80)
    plan_version = serializers.CharField(max_length=40, default="1.0")
    entitlements = serializers.JSONField()
    trial_days = serializers.IntegerField(min_value=0, max_value=365, default=30)

    def validate_entitlements(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("entitlements must be an object.")
        return value


class AuditeeOnboardingSerializer(serializers.Serializer):
    slug = serializers.SlugField(max_length=80)
    name = serializers.CharField(max_length=200)
    administrator_email = serializers.EmailField()
    auditee_mode = serializers.ChoiceField(choices=Tenant.AuditeeMode.choices, default=Tenant.AuditeeMode.FIRM_MANAGED)


class AuditorVerdictRequestSerializer(serializers.Serializer):
    organisation_control_id = serializers.UUIDField()
    decision = serializers.ChoiceField(choices=AuditorVerdict.Decision.choices)
    rationale = serializers.CharField(max_length=8000)
    evidence_result_id = serializers.UUIDField(required=False, allow_null=True)


SERIALIZERS = {
    Organization: OrganizationSerializer,
    Workspace: WorkspaceSerializer,
    Application: ApplicationSerializer,
    Membership: MembershipSerializer,
    TenantRelationship: TenantRelationshipSerializer,
    SubscriptionPlan: SubscriptionPlanSerializer,
    TenantSubscription: TenantSubscriptionSerializer,
    TenantEntitlement: TenantEntitlementSerializer,
    UsageRecord: UsageRecordSerializer,
    TenantBranding: TenantBrandingSerializer,
    TenantInvitation: TenantInvitationSerializer,
    Engagement: EngagementSerializer,
    EngagementScope: EngagementScopeSerializer,
    EngagementMember: EngagementMemberSerializer,
    EngagementStatusHistory: EngagementStatusHistorySerializer,
    Repository: RepositorySerializer,
    RepositoryVersion: RepositoryVersionSerializer,
    Job: JobSerializer,
    Scan: ScanSerializer,
    Finding: FindingSerializer,
    FindingEvidence: FindingEvidenceSerializer,
    ThreatModel: ThreatModelSerializer,
    ArchitectureComponent: ArchitectureComponentSerializer,
    DataFlow: DataFlowSerializer,
    Threat: ThreatSerializer,
    FrameworkVersion: FrameworkVersionSerializer,
    Requirement: RequirementSerializer,
    Framework: FrameworkSerializer,
    UnifiedControlObjective: UnifiedControlObjectiveSerializer,
    FrameworkControlMapping: FrameworkControlMappingSerializer,
    EvidenceRequirement: EvidenceRequirementSerializer,
    OrganisationControl: OrganisationControlSerializer,
    ControlAssignment: ControlAssignmentSerializer,
    ControlEvidenceLink: ControlEvidenceLinkSerializer,
    Assessment: AssessmentSerializer,
    AssessmentResponse: AssessmentResponseSerializer,
    AssessmentEvidence: AssessmentEvidenceSerializer,
    Evidence: EvidenceSerializer,
    ComplianceGap: ComplianceGapSerializer,
    Risk: RiskSerializer,
    RiskLink: RiskLinkSerializer,
    RiskScore: RiskScoreSerializer,
    Remediation: RemediationSerializer,
    Task: TaskSerializer,
    AssessmentObservation: AssessmentObservationSerializer,
    AuditorVerdict: AuditorVerdictSerializer,
    RiskAcceptance: RiskAcceptanceSerializer,
    Approval: ApprovalSerializer,
    ModelConfiguration: ModelConfigurationSerializer,
    PromptVersion: PromptVersionSerializer,
    AIAnalysisRun: AIAnalysisRunSerializer,
    Report: ReportSerializer,
    ServiceAccount: ServiceAccountSerializer,
    AuditEvent: serializer_for(AuditEvent, read_only_fields=tuple(field.name for field in AuditEvent._meta.fields)),
}
