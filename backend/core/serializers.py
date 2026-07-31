from django.utils import timezone
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
class FindingSerializer(TenantModelSerializer):
    class Meta:
        model = Finding
        fields = "__all__"
        read_only_fields = (
            "tenant", "version", "created_at", "updated_at", "scan", "repository_version",
            "rule_id", "rule_version", "analyzer_name", "analyzer_version", "analyzer_image_digest",
            "severity", "file_path", "start_line", "end_line", "evidence", "remediation", "fingerprint",
            "decision_at",
        )

    def update(self, instance, validated_data):
        if "analyst_decision" in validated_data and validated_data["analyst_decision"] != instance.analyst_decision:
            validated_data["decision_at"] = timezone.now()
        return super().update(instance, validated_data)


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
