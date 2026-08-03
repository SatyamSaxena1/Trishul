from rest_framework import serializers

from .ai_gateway import validate_endpoint
from .models import (
    AIAnalysisRun,
    Application,
    Approval,
    ArchitectureComponent,
    Assessment,
    AssessmentEvidence,
    AssessmentResponse,
    AuditEvent,
    ComplianceGap,
    DataFlow,
    Evidence,
    Finding,
    FindingEvidence,
    FindingReview,
    FrameworkVersion,
    Job,
    Membership,
    ModelConfiguration,
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
    TenantScopedModel,
    Threat,
    ThreatModel,
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
RepositorySerializer = serializer_for(Repository)
RepositoryVersionSerializer = serializer_for(RepositoryVersion, read_only_fields=("immutable",))
JobSerializer = serializer_for(Job)
ScanSerializer = serializer_for(Scan, read_only_fields=("state", "coverage"))
class FindingReviewSerializer(TenantModelSerializer):
    ALLOWED_REASON_CODES = {
        "confirmed_exploitable",
        "defense_in_depth",
        "test_or_nonproduction_code",
        "sanitized_or_unreachable",
        "scanner_misclassification",
        "same_root_cause",
        "insufficient_evidence",
        "owner_input_required",
    }

    class Meta:
        model = FindingReview
        fields = "__all__"
        read_only_fields = (
            "tenant", "version", "created_at", "updated_at", "reviewer", "reviewed_at", "finding_provenance"
        )

    def validate_reason_codes(self, value):
        if not isinstance(value, list) or len(value) > 5 or any(not isinstance(code, str) for code in value):
            raise serializers.ValidationError("Provide an array containing at most five reason codes.")
        if len(value) != len(set(value)):
            raise serializers.ValidationError("Reason codes must be unique.")
        unknown = set(value) - self.ALLOWED_REASON_CODES
        if unknown:
            raise serializers.ValidationError(f"Unsupported reason code(s): {', '.join(sorted(unknown))}.")
        return value


class FindingSerializer(TenantModelSerializer):
    analyst_decision = serializers.SerializerMethodField()
    decision_history = FindingReviewSerializer(source="reviews", many=True, read_only=True)

    class Meta:
        model = Finding
        fields = "__all__"
        read_only_fields = ("tenant", "version", "created_at", "updated_at", "status")

    def get_analyst_decision(self, obj):
        latest = obj.reviews.order_by("-reviewed_at", "-id").first()
        return FindingReviewSerializer(latest).data if latest else None


FindingEvidenceSerializer = serializer_for(FindingEvidence)
ThreatModelSerializer = serializer_for(ThreatModel)
ArchitectureComponentSerializer = serializer_for(ArchitectureComponent)
DataFlowSerializer = serializer_for(DataFlow)
ThreatSerializer = serializer_for(Threat)
FrameworkVersionSerializer = serializer_for(FrameworkVersion)
RequirementSerializer = serializer_for(Requirement)
AssessmentSerializer = serializer_for(Assessment)
EvidenceSerializer = serializer_for(Evidence, read_only_fields=("immutable",))
ComplianceGapSerializer = serializer_for(ComplianceGap)
AssessmentEvidenceSerializer = serializer_for(AssessmentEvidence)
RiskSerializer = serializer_for(Risk)
RiskLinkSerializer = serializer_for(RiskLink)
RemediationSerializer = serializer_for(Remediation)
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


SERIALIZERS = {
    Organization: OrganizationSerializer,
    Workspace: WorkspaceSerializer,
    Application: ApplicationSerializer,
    Membership: MembershipSerializer,
    Repository: RepositorySerializer,
    RepositoryVersion: RepositoryVersionSerializer,
    Job: JobSerializer,
    Scan: ScanSerializer,
    Finding: FindingSerializer,
    FindingReview: FindingReviewSerializer,
    FindingEvidence: FindingEvidenceSerializer,
    ThreatModel: ThreatModelSerializer,
    ArchitectureComponent: ArchitectureComponentSerializer,
    DataFlow: DataFlowSerializer,
    Threat: ThreatSerializer,
    FrameworkVersion: FrameworkVersionSerializer,
    Requirement: RequirementSerializer,
    Assessment: AssessmentSerializer,
    AssessmentResponse: AssessmentResponseSerializer,
    AssessmentEvidence: AssessmentEvidenceSerializer,
    Evidence: EvidenceSerializer,
    ComplianceGap: ComplianceGapSerializer,
    Risk: RiskSerializer,
    RiskLink: RiskLinkSerializer,
    RiskScore: RiskScoreSerializer,
    Remediation: RemediationSerializer,
    RiskAcceptance: RiskAcceptanceSerializer,
    Approval: ApprovalSerializer,
    ModelConfiguration: ModelConfigurationSerializer,
    PromptVersion: PromptVersionSerializer,
    AIAnalysisRun: AIAnalysisRunSerializer,
    Report: ReportSerializer,
    ServiceAccount: ServiceAccountSerializer,
    AuditEvent: serializer_for(AuditEvent, read_only_fields=tuple(field.name for field in AuditEvent._meta.fields)),
}
