import hashlib
import hmac
import html
import io
import json
import logging
import uuid
from datetime import timedelta

import httpx
import redis
from django.conf import settings
from django.db import connection, models, transaction
from django.db.models import Sum
from django.http import HttpResponse
from django.utils import timezone
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from rest_framework import exceptions, status, viewsets
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .ai_gateway import GatewayPolicyError, invoke
from .archive import UnsafeArchive, inspect_archive
from .entitlements import EntitlementDenied, enforce, record_usage
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
    CrossTenantAccessEvent,
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
    TenantSubscription,
    Threat,
    ThreatModel,
    UnifiedControlObjective,
    UsageRecord,
    Workspace,
)
from .risk import FORMULA_VERSION, calculate
from .security import ServicePrincipal, has_permission, principal_permissions, resolve_tenant
from .serializers import (
    SERIALIZERS,
    AuditeeOnboardingSerializer,
    AuditFirmOnboardingSerializer,
    AuditorVerdictRequestSerializer,
    TenantSummarySerializer,
)
from .storage import healthcheck as storage_healthcheck
from .storage import put_file
from .tenancy import engagement_target_context, tenant_context

logger = logging.getLogger(__name__)


class PreconditionRequired(exceptions.APIException):
    status_code = 428
    default_detail = "If-Match with the current resource version is required."
    default_code = "precondition_required"


class PreconditionFailed(exceptions.APIException):
    status_code = 412
    default_detail = "Resource version does not match."
    default_code = "precondition_failed"


PERMISSION_PREFIX = {
    Organization: "tenant",
    Workspace: "tenant",
    Application: "application",
    Membership: "membership",
    TenantRelationship: "engagement",
    SubscriptionPlan: "subscription",
    TenantSubscription: "subscription",
    TenantEntitlement: "subscription",
    UsageRecord: "usage",
    TenantBranding: "branding",
    TenantInvitation: "membership",
    Engagement: "engagement",
    EngagementScope: "engagement",
    EngagementMember: "engagement",
    EngagementStatusHistory: "engagement",
    Repository: "repository",
    RepositoryVersion: "repository",
    Job: "scan",
    Scan: "scan",
    Finding: "finding",
    FindingEvidence: "evidence",
    ThreatModel: "threat_model",
    ArchitectureComponent: "threat_model",
    DataFlow: "threat_model",
    Threat: "threat_model",
    FrameworkVersion: "assessment",
    Requirement: "assessment",
    Framework: "control",
    UnifiedControlObjective: "control",
    FrameworkControlMapping: "control",
    EvidenceRequirement: "control",
    OrganisationControl: "control",
    ControlAssignment: "control",
    ControlEvidenceLink: "evidence",
    Assessment: "assessment",
    AssessmentResponse: "assessment",
    AssessmentEvidence: "evidence",
    Evidence: "evidence",
    ComplianceGap: "assessment",
    Risk: "risk",
    RiskLink: "risk",
    RiskScore: "risk",
    Remediation: "finding",
    Task: "task",
    AssessmentObservation: "assessment",
    AuditorVerdict: "engagement",
    RiskAcceptance: "risk",
    Approval: "approval",
    ModelConfiguration: "policy",
    PromptVersion: "policy",
    AIAnalysisRun: "policy",
    Report: "report",
    ServiceAccount: "service_account",
    AuditEvent: "audit",
}

APPLICATION_PATH = {
    Application: "id",
    Repository: "application_id",
    RepositoryVersion: "repository__application_id",
    Job: "application_id",
    Scan: "repository_version__repository__application_id",
    Finding: "scan__repository_version__repository__application_id",
    FindingEvidence: "finding__scan__repository_version__repository__application_id",
    ThreatModel: "application_id",
    ArchitectureComponent: "threat_model__application_id",
    DataFlow: "threat_model__application_id",
    Threat: "threat_model__application_id",
    Assessment: "application_id",
    OrganisationControl: "application_id",
    ControlAssignment: "organisation_control__application_id",
    ControlEvidenceLink: "organisation_control__application_id",
    Evidence: "assessment__application_id",
    AssessmentResponse: "assessment__application_id",
    AssessmentEvidence: "response__assessment__application_id",
    ComplianceGap: "response__assessment__application_id",
    Risk: "application_id",
    RiskLink: "risk__application_id",
    RiskScore: "risk__application_id",
    Remediation: "risk__application_id",
    Task: "organisation_control__application_id",
    AssessmentObservation: "organisation_control__application_id",
    AuditorVerdict: "organisation_control__application_id",
    RiskAcceptance: "risk__application_id",
    Approval: "acceptance__risk__application_id",
    Report: "application_id",
}

WRITE_PERMISSION = {
    "tenant": "tenant.manage",
    "membership": "membership.manage",
    "application": "application.write",
    "repository": "repository.import",
    "scan": "scan.create",
    "finding": "finding.triage",
    "evidence": "assessment.write",
    "threat_model": "threat_model.write",
    "assessment": "assessment.write",
    "risk": "risk.override",
    "approval": "approval.decide",
    "policy": "policy.manage",
    "report": "report.create",
    "service_account": "service_account.manage",
    "audit": "audit.read",
    "subscription": "subscription.manage",
    "usage": "usage.read",
    "branding": "branding.manage",
    "engagement": "engagement.manage",
    "control": "control.manage",
    "task": "task.manage",
}


def actor(request):
    if isinstance(request.user, ServicePrincipal):
        return "service_account", str(request.user.id)
    return "user", str(request.user.id)


def application_restrictions(request):
    if isinstance(request.user, ServicePrincipal):
        return request.user.account.application_ids
    return request.membership.application_ids


def related_application_id(value):
    if isinstance(value, Application):
        return value.id
    path = APPLICATION_PATH.get(type(value))
    if not path:
        return None
    current = value
    for part in path.replace("_id", "").split("__"):
        current = getattr(current, part)
    return getattr(current, "id", current)


class TenantModelViewSet(viewsets.ModelViewSet):
    model = None
    serializer_class = None
    immutable = False

    def perform_authentication(self, request):
        super().perform_authentication(request)
        if not hasattr(request, "tenant"):
            resolve_tenant(request)

    def get_queryset(self):
        queryset = self.model.objects.all().order_by("-created_at")
        restrictions = application_restrictions(self.request)
        path = APPLICATION_PATH.get(self.model)
        return queryset.filter(**{f"{path}__in": restrictions}) if restrictions and path else queryset

    def get_required_permission(self):
        prefix = PERMISSION_PREFIX[self.model]
        if self.request.method in {"GET", "HEAD", "OPTIONS"}:
            candidate = f"{prefix}.read"
            if prefix == "tenant":
                candidate = "application.read"
            return candidate
        return WRITE_PERMISSION[prefix]

    def check_permissions(self, request):
        super().check_permissions(request)
        if not has_permission(request, self.get_required_permission()):
            raise exceptions.PermissionDenied("Permission is not granted for this operation.")

    def _audit(self, action_name, instance):
        actor_type, actor_id = actor(self.request)
        AuditEvent.append(
            tenant=self.request.tenant,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action_name,
            resource_type=self.model._meta.label_lower,
            resource_id=instance.pk,
            details={"version": instance.version},
        )

    def perform_create(self, serializer):
        extra = {"tenant": self.request.tenant}
        restrictions = application_restrictions(self.request)
        related_ids = {
            str(application_id)
            for value in serializer.validated_data.values()
            if (application_id := related_application_id(value))
        }
        if restrictions and (
            self.model is Application or any(application_id not in restrictions for application_id in related_ids)
        ):
            raise exceptions.PermissionDenied("Application scope does not permit this operation.")
        if self.model is RiskAcceptance:
            if isinstance(self.request.user, ServicePrincipal):
                raise exceptions.PermissionDenied("Service accounts cannot request risk acceptance.")
            extra["requested_by"] = self.request.user
        instance = serializer.save(**extra)
        self._audit("created", instance)

    def _match_version(self, instance):
        supplied = self.request.headers.get("If-Match")
        if supplied is None:
            raise PreconditionRequired()
        if supplied.strip('W/"') != str(instance.version):
            raise PreconditionFailed()

    def perform_update(self, serializer):
        if self.immutable:
            raise exceptions.MethodNotAllowed(self.request.method, "Resource is immutable.")
        with transaction.atomic():
            instance = self.model.objects.select_for_update().get(pk=serializer.instance.pk)
            self._match_version(instance)
            serializer.instance = instance
            updated = serializer.save(version=instance.version + 1)
            self._audit("updated", updated)

    def perform_destroy(self, instance):
        if self.immutable:
            raise exceptions.MethodNotAllowed(self.request.method, "Resource is immutable.")
        with transaction.atomic():
            instance = self.model.objects.select_for_update().get(pk=instance.pk)
            self._match_version(instance)
            self._audit("deleted", instance)
            instance.delete()


def viewset_for(model, *, immutable=False):
    return type(
        f"{model.__name__}ViewSet",
        (TenantModelViewSet,),
        {"model": model, "serializer_class": SERIALIZERS[model], "immutable": immutable},
    )


class ServiceAccountViewSet(viewset_for(ServiceAccount)):
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        account, token = ServiceAccount.issue(tenant=request.tenant, **serializer.validated_data)
        self._audit("created", account)
        data = self.get_serializer(account).data
        data["token"] = token
        return Response(data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        account = self.get_object()
        account.revoked_at = timezone.now()
        account.version += 1
        account.save(update_fields=["revoked_at", "version", "updated_at"])
        self._audit("revoked", account)
        return Response(status=status.HTTP_204_NO_CONTENT)


class RepositoryViewSet(viewset_for(Repository)):
    @action(detail=True, methods=["post"], url_path="imports")
    def import_archive(self, request, pk=None):
        repository = self.get_object()
        uploaded = request.FILES.get("archive")
        if not uploaded:
            raise exceptions.ValidationError({"archive": "A ZIP or TAR archive is required."})
        try:
            manifest = inspect_archive(uploaded)
        except UnsafeArchive as exc:
            raise exceptions.ValidationError({"archive": str(exc)}) from exc
        key = f"{request.tenant.id}/repositories/{repository.id}/{manifest['sha256']}.archive"
        put_file(key, uploaded, content_type=uploaded.content_type or "application/octet-stream")
        version, _ = RepositoryVersion.all_objects.get_or_create(
            tenant=request.tenant,
            repository=repository,
            sha256=manifest["sha256"],
            defaults={"object_key": key, "size": manifest["compressed_size"] or uploaded.size, "manifest": manifest},
        )
        self._audit("repository.imported", version)
        return Response(SERIALIZERS[RepositoryVersion](version).data, status=status.HTTP_201_CREATED)


class RiskViewSet(viewset_for(Risk)):
    @action(detail=True, methods=["post"], url_path="scores")
    def score(self, request, pk=None):
        risk = self.get_object()
        try:
            result = calculate(request.data)
        except (TypeError, ValueError) as exc:
            raise exceptions.ValidationError({"inputs": str(exc)}) from exc
        score = RiskScore.all_objects.create(
            tenant=request.tenant,
            risk=risk,
            formula_version=FORMULA_VERSION,
            inputs=request.data,
            inherent=result.inherent,
            residual=result.residual,
            priority=result.priority,
        )
        self._audit("risk.scored", score)
        return Response(SERIALIZERS[RiskScore](score).data, status=status.HTTP_201_CREATED)


class ScanViewSet(viewset_for(Scan)):
    def perform_create(self, serializer):
        if (
            serializer.validated_data.get("language_pack") != "python-stdlib"
            or serializer.validated_data.get("language_pack_version") != "1.0"
        ):
            raise exceptions.ValidationError(
                {"language_pack": "Only the experimental python-stdlib 1.0 pack is installed."}
            )
        super().perform_create(serializer)
        scan = serializer.instance
        Job.all_objects.create(
            tenant=self.request.tenant,
            application=scan.repository_version.repository.application,
            kind="scan",
            payload={"scan_id": str(scan.id)},
        )
        from .tasks import execute_scan

        transaction.on_commit(
            lambda: execute_scan.apply_async(args=[str(self.request.tenant.id), str(scan.id)], queue="analysis")
        )


class ThreatModelViewSet(viewset_for(ThreatModel)):
    @action(detail=True, methods=["post"])
    def generate(self, request, pk=None):
        model = self.get_object()
        components = list(model.components.all())
        flows = list(model.data_flows.all())
        if (
            not model.verified
            or not components
            or any(not component.verified for component in components)
            or any(not flow.verified for flow in flows)
        ):
            raise exceptions.ValidationError(
                {"verified": "The model, every component, and every flow must be human verified."}
            )
        created = []
        for flow in flows:
            if not flow.authenticated:
                created.append(
                    Threat.all_objects.create(
                        tenant=request.tenant,
                        threat_model=model,
                        component=flow.destination,
                        stride_category="Spoofing",
                        scenario=(
                            f"An unauthenticated actor may impersonate a caller on "
                            f"{flow.source.name} to {flow.destination.name}."
                        ),
                        likelihood=4,
                        impact=4,
                        controls=["Authenticate both endpoints", "Log authentication failures"],
                    )
                )
            if not flow.encrypted:
                created.append(
                    Threat.all_objects.create(
                        tenant=request.tenant,
                        threat_model=model,
                        component=flow.destination,
                        stride_category="Information disclosure",
                        scenario=(
                            f"Data on {flow.source.name} to {flow.destination.name} "
                            "may be observed or modified in transit."
                        ),
                        likelihood=4,
                        impact=4,
                        controls=["Require authenticated encryption in transit"],
                    )
                )
        for threat in created:
            self._audit("threat.generated", threat)
        return Response(SERIALIZERS[Threat](created, many=True).data, status=status.HTTP_201_CREATED)


class ApprovalViewSet(viewset_for(Approval, immutable=True)):
    def perform_create(self, serializer):
        if isinstance(self.request.user, ServicePrincipal):
            raise exceptions.PermissionDenied("Service accounts cannot approve risk acceptance.")
        acceptance = serializer.validated_data["acceptance"]
        if acceptance.requested_by_id == self.request.user.id:
            raise exceptions.ValidationError({"approver": "Requesters cannot approve their own acceptance."})
        approval = serializer.save(tenant=self.request.tenant, approver=self.request.user)
        acceptance.status = "approved" if approval.decision == "approved" else "rejected"
        acceptance.version += 1
        acceptance.save(update_fields=["status", "version", "updated_at"])
        self._audit("risk_acceptance.decided", approval)


class AssessmentResponseViewSet(viewset_for(AssessmentResponse)):
    def perform_update(self, serializer):
        decision = serializer.validated_data.get("decision")
        if decision in {AssessmentResponse.Decision.COMPLIANT, AssessmentResponse.Decision.NOT_APPLICABLE}:
            if isinstance(self.request.user, ServicePrincipal) or not has_permission(self.request, "assessment.review"):
                raise exceptions.PermissionDenied("A human assessor with review permission must make this conclusion.")
            serializer.validated_data["reviewed_by"] = self.request.user
        super().perform_update(serializer)


def _install_subscription(*, tenant, plan_key, plan_version, entitlements, trial_days=0):
    now = timezone.now()
    TenantSubscription.all_objects.create(
        tenant=tenant,
        plan_key=plan_key,
        plan_version=plan_version,
        entitlement_snapshot=entitlements,
        state=TenantSubscription.State.TRIAL if trial_days else TenantSubscription.State.ACTIVE,
        trial_started_at=now if trial_days else None,
        trial_ends_at=now + timedelta(days=trial_days) if trial_days else None,
    )
    for code, value in entitlements.items():
        TenantEntitlement.all_objects.create(
            tenant=tenant,
            code=code,
            enabled=value is not False,
            limit=value if isinstance(value, int) and not isinstance(value, bool) else None,
            configuration={"allow": value} if isinstance(value, list) else (value if isinstance(value, dict) else {}),
        )


def readonly_viewset_for(model):
    return type(
        f"{model.__name__}ReadOnlyViewSet",
        (TenantModelViewSet,),
        {
            "model": model,
            "serializer_class": SERIALIZERS[model],
            "immutable": True,
            "http_method_names": ["get", "head", "options"],
        },
    )


class TenantAdminViewSet(viewsets.ViewSet):
    """Narrow platform-admin path for audit-firm onboarding."""

    def perform_authentication(self, request):
        super().perform_authentication(request)
        if not hasattr(request, "tenant"):
            resolve_tenant(request)

    def check_permissions(self, request):
        super().check_permissions(request)
        if request.tenant.tenant_type != Tenant.Type.PLATFORM or not has_permission(request, "platform.manage"):
            raise exceptions.PermissionDenied("A platform administrator is required.")

    def list(self, request):
        firms = Tenant.objects.filter(tenant_type=Tenant.Type.AUDIT_FIRM).order_by("name")
        return Response(TenantSummarySerializer(firms, many=True).data)

    def create(self, request):
        serializer = AuditFirmOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if Tenant.objects.filter(slug=data["slug"]).exists():
            raise exceptions.ValidationError({"slug": "This tenant slug already exists."})
        with transaction.atomic():
            plan, created = SubscriptionPlan.all_objects.get_or_create(
                tenant=request.tenant,
                key=data["plan_key"],
                plan_version=data["plan_version"],
                defaults={"name": data["plan_key"].replace("-", " ").title(), "entitlements": data["entitlements"]},
            )
            if not created and plan.entitlements != data["entitlements"]:
                raise exceptions.ValidationError({"entitlements": "The plan version already has different terms."})
            firm = Tenant.objects.create(
                slug=data["slug"],
                name=data["name"],
                tenant_type=Tenant.Type.AUDIT_FIRM,
                isolation_tier=Tenant.IsolationTier.SHARED,
            )
            with tenant_context(firm.id):
                _install_subscription(
                    tenant=firm,
                    plan_key=plan.key,
                    plan_version=plan.plan_version,
                    entitlements=data["entitlements"],
                    trial_days=data["trial_days"],
                )
            TenantInvitation.all_objects.create(
                tenant=request.tenant,
                target_tenant=firm,
                email=data["administrator_email"],
                role=Membership.Role.FIRM_ADMIN,
                invited_by=request.user,
                expires_at=timezone.now() + timedelta(days=7),
            )
            AuditEvent.append(
                tenant=request.tenant,
                actor_type="user",
                actor_id=str(request.user.id),
                action="tenant.audit_firm.created",
                resource_type="core.tenant",
                resource_id=firm.id,
                details={"plan": f"{plan.key}@{plan.plan_version}", "isolation_tier": firm.isolation_tier},
            )
        return Response(TenantSummarySerializer(firm).data, status=status.HTTP_201_CREATED)


class OrganisationControlViewSet(viewset_for(OrganisationControl)):
    def get_required_permission(self):
        if self.request.membership.role == Membership.Role.CONTROL_OWNER:
            return "control.assigned"
        return super().get_required_permission()

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.membership.role == Membership.Role.CONTROL_OWNER:
            return queryset.filter(
                assignments__assignee=self.request.user,
                assignments__is_active=True,
            ).filter(
                models.Q(assignments__expires_at__isnull=True) | models.Q(assignments__expires_at__gt=timezone.now())
            )
        return queryset


class TaskViewSet(viewset_for(Task)):
    def get_required_permission(self):
        if self.request.membership.role == Membership.Role.CONTROL_OWNER:
            return "task.assigned"
        return super().get_required_permission()

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.membership.role == Membership.Role.CONTROL_OWNER:
            return queryset.filter(owner=self.request.user)
        return queryset


class EngagementMemberViewSet(viewset_for(EngagementMember)):
    def perform_create(self, serializer):
        user = serializer.validated_data["user"]
        if not Membership.all_objects.filter(tenant=self.request.tenant, user=user, is_active=True).exists():
            raise exceptions.ValidationError({"user": "The auditor must be an active firm member."})
        current = EngagementMember.objects.filter(is_active=True).values("user_id").distinct().count()
        try:
            enforce(self.request.tenant, "auditor_seats", current_usage=current)
        except EntitlementDenied as exc:
            raise exceptions.PermissionDenied(str(exc)) from exc
        super().perform_create(serializer)


class MembershipViewSet(viewset_for(Membership)):
    def _record_active_users(self, instance):
        record_usage(
            self.request.tenant,
            "active_users",
            Membership.objects.filter(is_active=True).count(),
            source_type="core.membership",
            source_id=instance.id,
            idempotency_key=f"active-users:{instance.id}:v{instance.version}",
        )

    def perform_create(self, serializer):
        super().perform_create(serializer)
        self._record_active_users(serializer.instance)

    def perform_update(self, serializer):
        super().perform_update(serializer)
        self._record_active_users(serializer.instance)


class TenantInvitationViewSet(viewset_for(TenantInvitation)):
    def perform_create(self, serializer):
        if isinstance(self.request.user, ServicePrincipal):
            raise exceptions.PermissionDenied("A human administrator must invite users.")
        expires_at = serializer.validated_data["expires_at"]
        if not timezone.now() < expires_at <= timezone.now() + timedelta(days=30):
            raise exceptions.ValidationError({"expires_at": "Invitations must expire within 30 days."})
        roles = {
            Tenant.Type.AUDIT_FIRM: {
                Membership.Role.FIRM_ADMIN,
                Membership.Role.AUDIT_MANAGER,
                Membership.Role.AUDITOR,
                Membership.Role.REVIEWER,
            },
            Tenant.Type.AUDITEE: {
                Membership.Role.ORG_ADMIN,
                Membership.Role.COMPLIANCE_MANAGER,
                Membership.Role.CONTROL_OWNER,
                Membership.Role.RISK_OWNER,
                Membership.Role.VENDOR_MANAGER,
                Membership.Role.CISO,
            },
        }
        if serializer.validated_data["role"] not in roles.get(self.request.tenant.tenant_type, set()):
            raise exceptions.ValidationError({"role": "This role is not valid for the tenant type."})
        invitation = serializer.save(
            tenant=self.request.tenant,
            target_tenant=self.request.tenant,
            invited_by=self.request.user,
        )
        self._audit("membership.invited", invitation)


class EngagementViewSet(viewset_for(Engagement)):
    def get_required_permission(self):
        if self.action in {"assurance_results"}:
            return "engagement.review"
        if self.action == "verdicts":
            return "engagement.review"
        return "engagement.read" if self.request.method in {"GET", "HEAD", "OPTIONS"} else "engagement.manage"

    def perform_create(self, serializer):
        auditee = serializer.validated_data["auditee_tenant"]
        if auditee.tenant_type != Tenant.Type.AUDITEE:
            raise exceptions.ValidationError({"auditee_tenant": "An auditee tenant is required."})
        if not TenantRelationship.objects.filter(related_tenant=auditee, status="active").exists():
            raise exceptions.ValidationError(
                {"auditee_tenant": "Create or link the auditee relationship before opening an engagement."}
            )
        for framework in serializer.validated_data.get("framework_scope", []):
            try:
                enforce(self.request.tenant, "frameworks", item=framework)
            except EntitlementDenied as exc:
                raise exceptions.PermissionDenied(str(exc)) from exc
        active = serializer.validated_data.get("status") == Engagement.Status.ACTIVE
        engagement = serializer.save(
            tenant=self.request.tenant,
            created_by=self.request.user,
            approved_by=self.request.user if active else None,
        )
        EngagementStatusHistory.all_objects.create(
            tenant=self.request.tenant,
            engagement=engagement,
            to_status=engagement.status,
            actor=self.request.user,
        )
        self._audit("engagement.created", engagement)

    def perform_update(self, serializer):
        previous = serializer.instance.status
        next_status = serializer.validated_data.get("status", previous)
        if next_status in {Engagement.Status.CLOSED, Engagement.Status.REVOKED} and not serializer.validated_data.get(
            "closed_reason", serializer.instance.closed_reason
        ):
            raise exceptions.ValidationError({"closed_reason": "Closing or revoking requires a reason."})
        super().perform_update(serializer)
        if next_status != previous:
            EngagementStatusHistory.all_objects.create(
                tenant=self.request.tenant,
                engagement=serializer.instance,
                from_status=previous,
                to_status=next_status,
                reason=serializer.instance.closed_reason,
                actor=self.request.user,
            )

    @action(detail=False, methods=["post"], url_path="onboard-auditee")
    def onboard_auditee(self, request):
        serializer = AuditeeOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        current = TenantRelationship.objects.filter(
            relationship=TenantRelationship.Relationship.MANAGES, status="active"
        ).count()
        try:
            enforce(request.tenant, "auditee_organisations", current_usage=current)
        except EntitlementDenied as exc:
            raise exceptions.PermissionDenied(str(exc)) from exc
        if Tenant.objects.filter(slug=data["slug"]).exists():
            raise exceptions.ValidationError({"slug": "This tenant slug already exists."})
        subscription = TenantSubscription.objects.order_by("-created_at").first()
        with transaction.atomic():
            auditee = Tenant.objects.create(
                slug=data["slug"],
                name=data["name"],
                tenant_type=Tenant.Type.AUDITEE,
                auditee_mode=data["auditee_mode"],
            )
            TenantRelationship.all_objects.create(
                tenant=request.tenant,
                related_tenant=auditee,
                relationship=TenantRelationship.Relationship.MANAGES,
            )
            record_usage(
                request.tenant,
                "active_auditee_organisations",
                1,
                source_type="core.tenant",
                source_id=auditee.id,
                idempotency_key=f"auditee:{auditee.id}",
            )
            TenantInvitation.all_objects.create(
                tenant=request.tenant,
                target_tenant=auditee,
                email=data["administrator_email"],
                role=Membership.Role.ORG_ADMIN,
                invited_by=request.user,
                expires_at=timezone.now() + timedelta(days=7),
            )
            if subscription:
                with tenant_context(auditee.id):
                    _install_subscription(
                        tenant=auditee,
                        plan_key=subscription.plan_key,
                        plan_version=subscription.plan_version,
                        entitlements=subscription.entitlement_snapshot,
                    )
            with tenant_context(auditee.id):
                organization = Organization.all_objects.create(tenant=auditee, name=auditee.name)
                Workspace.all_objects.create(tenant=auditee, organization=organization, name="Default")
            AuditEvent.append(
                tenant=request.tenant,
                actor_type="user",
                actor_id=str(request.user.id),
                action="tenant.auditee.created",
                resource_type="core.tenant",
                resource_id=auditee.id,
                details={"mode": auditee.auditee_mode},
            )
        return Response(TenantSummarySerializer(auditee).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="link-auditee")
    def link_auditee(self, request):
        try:
            auditee = Tenant.objects.get(pk=uuid.UUID(str(request.data["auditee_tenant_id"])))
        except (KeyError, ValueError, Tenant.DoesNotExist) as exc:
            raise exceptions.ValidationError({"auditee_tenant_id": "A valid auditee tenant is required."}) from exc
        if auditee.tenant_type != Tenant.Type.AUDITEE:
            raise exceptions.ValidationError({"auditee_tenant_id": "An auditee tenant is required."})
        current = TenantRelationship.objects.filter(
            relationship=TenantRelationship.Relationship.MANAGES, status="active"
        ).count()
        if not TenantRelationship.objects.filter(related_tenant=auditee, status="active").exists():
            try:
                enforce(request.tenant, "auditee_organisations", current_usage=current)
            except EntitlementDenied as exc:
                raise exceptions.PermissionDenied(str(exc)) from exc
        relationship, _ = TenantRelationship.objects.get_or_create(
            tenant=request.tenant,
            related_tenant=auditee,
            relationship=TenantRelationship.Relationship.CLIENT,
            defaults={"status": "active"},
        )
        record_usage(
            request.tenant,
            "active_auditee_organisations",
            1,
            source_type="core.tenantrelationship",
            source_id=relationship.id,
            idempotency_key=f"auditee:{auditee.id}",
        )
        return Response(SERIALIZERS[TenantRelationship](relationship).data, status=status.HTTP_201_CREATED)

    def _access(self, engagement, *, action_name, object_type, object_id="", write=False):
        reason = "active_scoped_engagement"
        allowed = engagement.is_live()
        member = None
        if allowed and self.request.membership.role not in {Membership.Role.FIRM_ADMIN, Membership.Role.AUDIT_MANAGER}:
            member = EngagementMember.objects.filter(
                engagement=engagement, user=self.request.user, is_active=True
            ).first()
            allowed = member is not None and not (write and member.role == EngagementMember.Role.REVIEWER)
            if not member:
                reason = "auditor_not_assigned"
            elif write and member.role == EngagementMember.Role.REVIEWER:
                reason = "reviewer_is_read_only"
        elif not allowed:
            reason = "engagement_not_active_or_outside_dates"
        CrossTenantAccessEvent.all_objects.create(
            tenant=self.request.tenant,
            target_tenant=engagement.auditee_tenant,
            engagement=engagement,
            subject_id=str(self.request.user.id),
            object_type=object_type,
            object_id=str(object_id),
            action=action_name,
            decision="allow" if allowed else "deny",
            reason=reason,
        )
        return allowed

    def _scope_access(self, engagement, *, action_name, object_type, object_id, allowed):
        # The ORM context points at the auditee while this audit row belongs to
        # the firm. PostgreSQL retains the request's firm tenant GUC.
        with tenant_context(self.request.tenant.id):
            CrossTenantAccessEvent.all_objects.create(
                tenant=self.request.tenant,
                target_tenant=engagement.auditee_tenant,
                engagement=engagement,
                subject_id=str(self.request.user.id),
                object_type=object_type,
                object_id=str(object_id),
                action=action_name,
                decision="allow" if allowed else "deny",
                reason="active_scoped_engagement" if allowed else "object_outside_engagement_scope",
            )
        return allowed

    @staticmethod
    def _access_denied(detail="The engagement does not grant this access."):
        # Raising APIException marks an ATOMIC_REQUESTS transaction for
        # rollback, which would erase the denial audit row.
        return Response({"detail": detail}, status=status.HTTP_403_FORBIDDEN)

    def _control_in_scope(self, engagement, control):
        applications = {str(item) for item in engagement.application_scope}
        controls = set(engagement.control_scope)
        return (not applications or str(control.application_id) in applications) and (
            not controls or control.unified_control.code in controls
        )

    @action(detail=True, methods=["get"], url_path="assurance-results")
    def assurance_results(self, request, pk=None):
        engagement = self.get_object()
        target_id = request.query_params.get("target_id", "")
        if not self._access(
            engagement,
            action_name="deployment_assurance.read",
            object_type="deployment_assurance.target",
            object_id=target_id,
        ):
            return self._access_denied()
        from deployment_assurance.models import DeploymentDecision
        from deployment_assurance.serializers import DeploymentDecisionSerializer

        with engagement_target_context(engagement.auditee_tenant_id, engagement.id):
            decisions = DeploymentDecision.all_objects.filter(tenant=engagement.auditee_tenant).select_related(
                "target", "evaluation_run"
            )
            if engagement.application_scope:
                decisions = decisions.filter(target__application_id__in=engagement.application_scope)
            if target_id:
                decisions = decisions.filter(target_id=target_id)
            payload = []
            for decision in decisions.order_by("-created_at")[:50]:
                item = DeploymentDecisionSerializer(decision).data
                results = decision.evaluation_run.results.select_related("policy_rule", "gap", "risk")
                item["framework_impact"] = sorted(
                    {
                        f"{mapping.framework} {mapping.framework_version} {mapping.control_id}"
                        for result in results
                        for mapping in result.policy_rule.mappings.all()
                    }
                )
                item["related_gap_ids"] = sorted({str(result.gap_id) for result in results if result.gap_id})
                item["related_risk_ids"] = sorted({str(result.risk_id) for result in results if result.risk_id})
                payload.append(item)
        return Response(payload)

    @action(detail=True, methods=["post"])
    def verdicts(self, request, pk=None):
        engagement = self.get_object()
        # Reject an inactive or unassigned engagement before entering the
        # auditee context; the object-level decision is recorded after lookup.
        if not self._access(
            engagement,
            action_name="auditor_verdict.create",
            object_type="core.engagement",
            object_id=request.data.get("organisation_control_id", ""),
            write=True,
        ):
            return self._access_denied()
        serializer = AuditorVerdictRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        with engagement_target_context(engagement.auditee_tenant_id, engagement.id):
            try:
                control = OrganisationControl.all_objects.get(
                    tenant=engagement.auditee_tenant, pk=data["organisation_control_id"]
                )
            except OrganisationControl.DoesNotExist as exc:
                raise exceptions.ValidationError({"organisation_control_id": "No in-scope control exists."}) from exc
            if not self._scope_access(
                engagement,
                action_name="auditor_verdict.create",
                object_type="core.organisationcontrol",
                object_id=control.id,
                allowed=self._control_in_scope(engagement, control),
            ):
                return self._access_denied("The object is outside the engagement scope.")
            previous = (
                AuditorVerdict.all_objects.filter(
                    tenant=engagement.auditee_tenant,
                    engagement_id=engagement.id,
                    organisation_control=control,
                )
                .order_by("-finalized_at")
                .first()
            )
            if previous and previous.locked:
                raise exceptions.ValidationError({"control": "The control is locked; unlock it before re-review."})
            result_id = data.get("evidence_result_id")
            if result_id:
                from deployment_assurance.models import ControlResult

                try:
                    result = ControlResult.all_objects.select_related("evaluation_run").get(
                        tenant=engagement.auditee_tenant, pk=result_id
                    )
                except ControlResult.DoesNotExist as exc:
                    raise exceptions.ValidationError({"evidence_result_id": "No in-scope result exists."}) from exc
                if result.evaluation_run.requested_by_id == str(request.user.id):
                    raise exceptions.PermissionDenied("An evidence submitter cannot record its auditor verdict.")
            verdict = AuditorVerdict.all_objects.create(
                tenant=engagement.auditee_tenant,
                engagement_id=engagement.id,
                organisation_control=control,
                decision=data["decision"],
                rationale=data["rationale"],
                evidence_result_id=result_id,
                finalized_by=request.user,
                supersedes=previous,
            )
            control_status = (
                OrganisationControl.Status.UNDER_REVIEW
                if data["decision"] == AuditorVerdict.Decision.QUERY_RAISED
                else data["decision"]
            )
            OrganisationControl.all_objects.filter(pk=control.pk).update(
                status=control_status, last_reviewed_at=timezone.now(), version=control.version + 1
            )
        return Response(SERIALIZERS[AuditorVerdict](verdict).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="unlock-control")
    def unlock_control(self, request, pk=None):
        engagement = self.get_object()
        if not self._access(
            engagement,
            action_name="auditor_control.unlock",
            object_type="core.engagement",
            object_id=request.data.get("organisation_control_id", ""),
            write=True,
        ):
            return self._access_denied()
        try:
            control_id = uuid.UUID(str(request.data["organisation_control_id"]))
            reason = str(request.data["reason"]).strip()
        except (KeyError, ValueError) as exc:
            raise exceptions.ValidationError({"detail": "organisation_control_id and reason are required."}) from exc
        if not reason:
            raise exceptions.ValidationError({"reason": "An unlock reason is required."})
        with engagement_target_context(engagement.auditee_tenant_id, engagement.id):
            previous = (
                AuditorVerdict.all_objects.filter(
                    tenant=engagement.auditee_tenant,
                    engagement_id=engagement.id,
                    organisation_control_id=control_id,
                )
                .order_by("-finalized_at")
                .first()
            )
            if previous is None or not previous.locked:
                raise exceptions.ValidationError({"control": "The control is not locked."})
            if not self._scope_access(
                engagement,
                action_name="auditor_control.unlock",
                object_type="core.organisationcontrol",
                object_id=control_id,
                allowed=self._control_in_scope(engagement, previous.organisation_control),
            ):
                return self._access_denied("The object is outside the engagement scope.")
            unlocked = AuditorVerdict.all_objects.create(
                tenant=engagement.auditee_tenant,
                engagement_id=engagement.id,
                organisation_control=previous.organisation_control,
                decision=previous.decision,
                rationale=f"Unlocked: {reason}",
                evidence_result_id=previous.evidence_result_id,
                finalized_by=request.user,
                locked=False,
                supersedes=previous,
            )
        return Response(SERIALIZERS[AuditorVerdict](unlocked).data, status=status.HTTP_201_CREATED)


class ReportViewSet(viewset_for(Report, immutable=True)):
    http_method_names = ["get", "post", "head", "options"]

    def create(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed("POST", "Use the reports/generate action.")

    @action(detail=False, methods=["post"])
    def generate(self, request):
        if isinstance(request.user, ServicePrincipal):
            raise exceptions.PermissionDenied("A human user must generate a report.")
        try:
            application = Application.objects.get(pk=request.data["application_id"])
        except (KeyError, Application.DoesNotExist) as exc:
            raise exceptions.ValidationError({"application_id": "A visible application is required."}) from exc
        report_type = request.data.get("report_type", "technical")
        if report_type not in {"technical", "executive"}:
            raise exceptions.ValidationError({"report_type": "Use technical or executive."})
        findings = list(
            Finding.objects.filter(scan__repository_version__repository__application=application).values(
                "id", "title", "severity", "confidence", "status", "cwe"
            )
        )
        threats = list(
            Threat.objects.filter(threat_model__application=application).values(
                "id", "stride_category", "scenario", "likelihood", "impact", "status"
            )
        )
        assessments = list(Assessment.objects.filter(application=application).values("id", "name", "status"))
        risks = list(Risk.objects.filter(application=application).values("id", "title", "state"))
        snapshot = {
            "format": "ai-trishul-report-v1",
            "type": report_type,
            "generated_at": timezone.now().isoformat(),
            "application": {"id": str(application.id), "name": application.name},
            "findings": findings,
            "threats": threats,
            "assessments": assessments,
            "risks": risks,
        }
        json_bytes = json.dumps(snapshot, sort_keys=True, default=str, separators=(",", ":")).encode()
        content_hash = hashlib.sha256(json_bytes).hexdigest()
        rows = findings if report_type == "technical" else risks
        row_html = "".join(
            f"<li><strong>{html.escape(str(item.get('title', item.get('name', 'Item'))))}</strong>"
            f" — {html.escape(str(item.get('status', item.get('state', 'open'))))}</li>"
            for item in rows
        )
        html_bytes = (
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>AI Trishul report</title><body>"
            f"<h1>{html.escape(application.name)} — {html.escape(report_type.title())} Security Report</h1>"
            f"<p>Snapshot SHA-256: <code>{content_hash}</code></p>"
            f"<p>{len(findings)} findings · {len(threats)} threats · "
            f"{len(assessments)} assessments · {len(risks)} risks</p>"
            f"<ul>{row_html}</ul></body></html>"
        ).encode()
        report_id = uuid.uuid4()
        base_key = f"{request.tenant.id}/reports/{application.id}/{report_id}"
        put_file(f"{base_key}.json", io.BytesIO(json_bytes), content_type="application/json")
        put_file(f"{base_key}.html", io.BytesIO(html_bytes), content_type="text/html")
        report = Report.all_objects.create(
            id=report_id,
            tenant=request.tenant,
            application=application,
            report_type=report_type,
            object_key=f"{base_key}.html",
            content_hash=content_hash,
            source_versions={
                "json_object_key": f"{base_key}.json",
                "application_version": application.version,
            },
            generated_by=request.user,
        )
        self._audit("report.generated", report)
        return Response(SERIALIZERS[Report](report).data, status=status.HTTP_201_CREATED)


class AuditEventViewSet(viewset_for(AuditEvent, immutable=True)):
    http_method_names = ["get", "head", "options"]


MODEL_VIEWSETS = {
    "tenant-admin": TenantAdminViewSet,
    "organizations": viewset_for(Organization),
    "workspaces": viewset_for(Workspace),
    "applications": viewset_for(Application),
    "memberships": MembershipViewSet,
    "tenant-relationships": readonly_viewset_for(TenantRelationship),
    "subscription-plans": viewset_for(SubscriptionPlan),
    "tenant-subscriptions": readonly_viewset_for(TenantSubscription),
    "tenant-entitlements": readonly_viewset_for(TenantEntitlement),
    "usage-records": readonly_viewset_for(UsageRecord),
    "tenant-branding": viewset_for(TenantBranding),
    "tenant-invitations": TenantInvitationViewSet,
    "engagements": EngagementViewSet,
    "engagement-scopes": viewset_for(EngagementScope),
    "engagement-members": EngagementMemberViewSet,
    "engagement-status-history": readonly_viewset_for(EngagementStatusHistory),
    "repositories": RepositoryViewSet,
    "repository-versions": viewset_for(RepositoryVersion, immutable=True),
    "jobs": viewset_for(Job),
    "scans": ScanViewSet,
    "findings": viewset_for(Finding),
    "finding-evidence": viewset_for(FindingEvidence, immutable=True),
    "threat-models": ThreatModelViewSet,
    "architecture-components": viewset_for(ArchitectureComponent),
    "data-flows": viewset_for(DataFlow),
    "threats": viewset_for(Threat),
    "framework-versions": viewset_for(FrameworkVersion, immutable=True),
    "requirements": viewset_for(Requirement, immutable=True),
    "frameworks": readonly_viewset_for(Framework),
    "unified-controls": readonly_viewset_for(UnifiedControlObjective),
    "control-mappings": readonly_viewset_for(FrameworkControlMapping),
    "evidence-requirements": readonly_viewset_for(EvidenceRequirement),
    "organisation-controls": OrganisationControlViewSet,
    "control-assignments": viewset_for(ControlAssignment),
    "control-evidence-links": readonly_viewset_for(ControlEvidenceLink),
    "assessments": viewset_for(Assessment),
    "assessment-responses": AssessmentResponseViewSet,
    "assessment-evidence": viewset_for(AssessmentEvidence, immutable=True),
    "evidence": viewset_for(Evidence, immutable=True),
    "compliance-gaps": viewset_for(ComplianceGap),
    "risks": RiskViewSet,
    "risk-links": viewset_for(RiskLink),
    "risk-scores": viewset_for(RiskScore, immutable=True),
    "remediations": viewset_for(Remediation),
    "tasks": TaskViewSet,
    "assessment-observations": readonly_viewset_for(AssessmentObservation),
    "auditor-verdicts": readonly_viewset_for(AuditorVerdict),
    "risk-acceptances": viewset_for(RiskAcceptance),
    "approvals": ApprovalViewSet,
    "model-configurations": viewset_for(ModelConfiguration),
    "prompt-versions": viewset_for(PromptVersion, immutable=True),
    "ai-runs": viewset_for(AIAnalysisRun, immutable=True),
    "reports": ReportViewSet,
    "service-accounts": ServiceAccountViewSet,
    "audit-events": AuditEventViewSet,
}


@api_view(["GET"])
def context(request):
    resolve_tenant(request)
    membership = getattr(request, "membership", None)
    return Response(
        {
            "tenant": {"id": request.tenant.id, "name": request.tenant.name},
            "principal": {
                "id": request.user.id,
                "name": request.user.username,
                "type": "service_account" if isinstance(request.user, ServicePrincipal) else "user",
            },
            "role": membership.role if membership else None,
            "permissions": sorted(principal_permissions(request)),
        }
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def oidc_config(request):
    return Response(
        {
            "authority": settings.OIDC_ISSUER,
            "client_id": settings.OIDC_CLIENT_ID,
            "audience": settings.OIDC_AUDIENCE,
            "redirect_uri": request.build_absolute_uri("/auth/callback"),
            "scope": "openid profile email",
        }
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def oidc_metadata(request):
    if not settings.OIDC_ISSUER:
        return Response({"detail": "OIDC is not configured."}, status=503)
    discovery_url = settings.OIDC_DISCOVERY_URL or (
        f"{settings.OIDC_ISSUER.rstrip('/')}/.well-known/openid-configuration"
    )
    if not discovery_url.startswith("https://"):
        return Response({"detail": "OIDC discovery must use HTTPS."}, status=503)
    try:
        response = httpx.get(
            discovery_url,
            timeout=5,
            follow_redirects=False,
            verify=settings.OIDC_CA_BUNDLE,
        )
        response.raise_for_status()
        metadata = response.json()
        if metadata.get("issuer") != settings.OIDC_ISSUER:
            raise ValueError("OIDC discovery issuer mismatch")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not str(metadata.get(key, "")).startswith("https://"):
                raise ValueError(f"OIDC {key} must use HTTPS")
        return Response(metadata)
    except (httpx.HTTPError, ValueError):
        logger.exception("OIDC discovery failed")
        return Response({"detail": "OIDC discovery is unavailable."}, status=503)


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def live(request):
    return Response({"status": "live"})


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def ready(request):
    checks = {}
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception:
        logger.exception("Database readiness failed")
        checks["database"] = "failed"
    try:
        redis.from_url(settings.CELERY_BROKER_URL, socket_timeout=2).ping()
        checks["queue"] = "ok"
    except Exception:
        logger.exception("Queue readiness failed")
        checks["queue"] = "failed"
    if settings.S3_BUCKET:
        try:
            storage_healthcheck()
            checks["object_storage"] = "ok"
        except Exception:
            logger.exception("Object storage readiness failed")
            checks["object_storage"] = "failed"
    else:
        checks["object_storage"] = "unconfigured"
    healthy = all(value == "ok" for value in checks.values())
    return Response({"status": "ready" if healthy else "not_ready", "checks": checks}, status=200 if healthy else 503)


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def metrics(request):
    configured = bool(settings.METRICS_TOKEN)
    expected = hashlib.sha256(settings.METRICS_TOKEN.encode()).hexdigest()
    supplied = request.headers.get("X-Metrics-Token", "")
    if configured and not hmac.compare_digest(hashlib.sha256(supplied.encode()).hexdigest(), expected):
        return Response(status=403)
    return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def ai_invoke(request):
    if not settings.INTERNAL_AI_TOKEN or not hmac.compare_digest(
        request.headers.get("X-Internal-Token", ""), settings.INTERNAL_AI_TOKEN
    ):
        return Response(status=403)
    try:
        tenant_id = request.data["tenant_id"]
        from .tenancy import set_current_tenant

        set_current_tenant(tenant_id)
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])
        configuration = ModelConfiguration.all_objects.get(
            tenant_id=tenant_id, id=request.data["model_configuration_id"], is_active=True
        )
        classification = request.data["data_classification"]
        if classification not in configuration.allowed_data_classes:
            raise GatewayPolicyError("Tenant policy forbids this data classification.")
        prompt_version = PromptVersion.all_objects.get(
            tenant_id=tenant_id,
            id=request.data["prompt_version_id"],
            approved_at__isnull=False,
        )
        now = timezone.now()
        recent = AIAnalysisRun.all_objects.filter(
            tenant_id=tenant_id,
            model_configuration=configuration,
            created_at__gte=now - timedelta(minutes=1),
        ).count()
        if recent >= configuration.requests_per_minute:
            return Response({"error": "rate_limited"}, status=429)
        used_today = (
            AIAnalysisRun.all_objects.filter(
                tenant_id=tenant_id,
                model_configuration=configuration,
                created_at__date=now.date(),
            ).aggregate(total=Sum("input_tokens") + Sum("output_tokens"))["total"]
            or 0
        )
        estimated_input = sum(len(str(item.get("content", ""))) for item in request.data["messages"]) // 4
        if used_today + estimated_input + configuration.max_output_tokens > configuration.daily_token_limit:
            return Response({"error": "daily_token_budget_exceeded"}, status=429)
        enforce(
            configuration.tenant,
            "ai_credits",
            quantity=estimated_input + configuration.max_output_tokens,
        )
        output, metadata = invoke(
            configuration=configuration,
            workflow=request.data["workflow"],
            messages=request.data["messages"],
            response_schema=request.data["response_schema"],
        )
        run = AIAnalysisRun.all_objects.create(
            tenant_id=tenant_id,
            model_configuration=configuration,
            prompt_version=prompt_version,
            workflow=request.data["workflow"],
            state="accepted",
            request_hash=metadata["request_hash"],
            response_hash=metadata["response_hash"],
            input_tokens=metadata["input_tokens"],
            output_tokens=metadata["output_tokens"],
            policy_decisions=[f"classification:{classification}:allowed", "structured_output:valid"],
        )
        record_usage(
            configuration.tenant,
            "ai_credits",
            run.input_tokens + run.output_tokens,
            source_type="core.aianalysisrun",
            source_id=run.id,
            idempotency_key=f"ai:{run.id}",
        )
        AuditEvent.append(
            tenant=configuration.tenant,
            actor_type="system",
            actor_id="ai-gateway",
            action="ai.analysis.accepted",
            resource_type="core.aianalysisrun",
            resource_id=run.id,
            details={
                "workflow": run.workflow,
                "model_configuration_id": str(configuration.id),
                "prompt_version_id": str(prompt_version.id),
                "input_tokens": run.input_tokens,
                "output_tokens": run.output_tokens,
            },
        )
        return Response({"output": output, "metadata": metadata})
    except (
        KeyError,
        ModelConfiguration.DoesNotExist,
        PromptVersion.DoesNotExist,
        EntitlementDenied,
        GatewayPolicyError,
        ValueError,
    ) as exc:
        return Response({"error": type(exc).__name__, "detail": str(exc)}, status=400)
