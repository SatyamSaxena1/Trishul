from rest_framework import serializers

from .ai_gateway import validate_endpoint
from .credentials import encrypt_credential, encrypt_secret
from .integrations import validate_clone_url, validate_staging_url
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
    StagingTarget,
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


class RepositorySerializer(TenantModelSerializer):
    credential = serializers.CharField(write_only=True, required=False, allow_blank=True)
    status_credential = serializers.CharField(write_only=True, required=False, allow_blank=True)
    webhook_secret = serializers.CharField(write_only=True, required=False, allow_blank=True)
    ci_secret = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = Repository
        fields = tuple(
            field.name for field in Repository._meta.fields if not field.name.endswith("_ciphertext")
        ) + ("credential", "status_credential", "webhook_secret", "ci_secret")
        read_only_fields = (
            "tenant",
            "version",
            "created_at",
            "updated_at",
        )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        source_type = attrs.get("source_type", getattr(self.instance, "source_type", "upload"))
        clone_url = attrs.get("clone_url", getattr(self.instance, "clone_url", ""))
        if source_type != Repository.SourceType.UPLOAD:
            if not clone_url or not attrs.get("external_id", getattr(self.instance, "external_id", "")):
                raise serializers.ValidationError("Git repositories require clone_url and external_id.")
            validate_clone_url(source_type, clone_url)
            if not attrs.get("webhook_secret") and not getattr(self.instance, "webhook_secret_ciphertext", ""):
                raise serializers.ValidationError({"webhook_secret": "A webhook secret is required."})
            if source_type == Repository.SourceType.GITHUB and not attrs.get(
                "installation_id", getattr(self.instance, "installation_id", "")
            ):
                raise serializers.ValidationError({"installation_id": "A GitHub installation ID is required."})
            if source_type == Repository.SourceType.GITLAB and not attrs.get("credential") and not getattr(
                self.instance, "credential_ciphertext", ""
            ):
                raise serializers.ValidationError({"credential": "A GitLab read-only token is required."})
        return attrs

    def _secrets(self, validated_data):
        for name, target in (
            ("credential", "credential_ciphertext"),
            ("status_credential", "status_credential_ciphertext"),
            ("webhook_secret", "webhook_secret_ciphertext"),
            ("ci_secret", "ci_secret_ciphertext"),
        ):
            if name in validated_data:
                value = validated_data.pop(name)
                validated_data[target] = (
                    encrypt_credential(value) if name in {"credential", "status_credential"} else encrypt_secret(value)
                )
        return validated_data

    def create(self, validated_data):
        return super().create(self._secrets(validated_data))

    def update(self, instance, validated_data):
        return super().update(instance, self._secrets(validated_data))


RepositoryVersionSerializer = serializer_for(RepositoryVersion, read_only_fields=("immutable",))
JobSerializer = serializer_for(Job)
ScanSerializer = serializer_for(Scan, read_only_fields=("state", "coverage"))
FindingSerializer = serializer_for(Finding)
FindingEvidenceSerializer = serializer_for(FindingEvidence)


class StagingTargetSerializer(TenantModelSerializer):
    class Meta:
        model = StagingTarget
        fields = "__all__"
        read_only_fields = ("tenant", "version", "created_at", "updated_at")

    def validate_url(self, value):
        return validate_staging_url(value)


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
    StagingTarget: StagingTargetSerializer,
    AuditEvent: serializer_for(AuditEvent, read_only_fields=tuple(field.name for field in AuditEvent._meta.fields)),
}
