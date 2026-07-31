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
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, connection, transaction
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
    Threat,
    ThreatModel,
    Workspace,
)
from .risk import FORMULA_VERSION, calculate
from .security import ServicePrincipal, has_permission, principal_permissions, resolve_tenant
from .serializers import SERIALIZERS
from .storage import healthcheck as storage_healthcheck
from .storage import put_file

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
    Assessment: "assessment",
    AssessmentResponse: "assessment",
    AssessmentEvidence: "evidence",
    Evidence: "evidence",
    ComplianceGap: "assessment",
    Risk: "risk",
    RiskLink: "risk",
    RiskScore: "risk",
    Remediation: "finding",
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
    Evidence: "assessment__application_id",
    AssessmentResponse: "assessment__application_id",
    AssessmentEvidence: "response__assessment__application_id",
    ComplianceGap: "response__assessment__application_id",
    Risk: "application_id",
    RiskLink: "risk__application_id",
    RiskScore: "risk__application_id",
    Remediation: "risk__application_id",
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
    def _submission_key(self, data):
        repository_version = data["repository_version"]
        explicit = self.request.headers.get("Idempotency-Key") or self.request.data.get("idempotency_key")
        if explicit is not None and (not isinstance(explicit, str) or not explicit.strip() or len(explicit) > 200):
            raise exceptions.ValidationError(
                {"idempotency_key": "Must be a non-empty string of at most 200 characters."}
            )
        material = {
            "repository_version": str(repository_version.id),
            "repository_sha256": repository_version.sha256,
            "analyzer": data["language_pack"],
            "analyzer_version": data["language_pack_version"],
            "configuration": data.get("configuration", {}),
            "enabled_rules": sorted(set(data.get("enabled_rules", []))),
            # An explicit key scopes retries of one caller operation, while all
            # immutable analysis inputs prevent accidental key reuse.
            "client_key": explicit.strip() if explicit else None,
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def create(self, request, *args, **kwargs):
        # idempotency_key is an API-only field and is deliberately not persisted
        # in plaintext.
        submitted = request.data.copy()
        submitted.pop("idempotency_key", None)
        serializer = self.get_serializer(data=submitted)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if data.get("language_pack") != "python-stdlib" or data.get("language_pack_version") != "1.0":
            raise exceptions.ValidationError(
                {"language_pack": "Only the experimental python-stdlib 1.0 pack is installed."}
            )
        key = self._submission_key(data)
        existing = Job.all_objects.filter(
            tenant=request.tenant,
            idempotency_key=key,
            state__in=[Job.State.QUEUED, Job.State.RUNNING, Job.State.COMPLETED],
        ).first()
        created = False
        if existing is None:
            try:
                with transaction.atomic():
                    scan = serializer.save(tenant=request.tenant, coverage={"status": "pending"})
                    existing = Job.all_objects.create(
                        tenant=request.tenant,
                        application=scan.repository_version.repository.application,
                        kind="scan",
                        payload={"scan_id": str(scan.id)},
                        idempotency_key=key,
                    )
                    created = True
            except (IntegrityError, DjangoValidationError):
                # A concurrent transaction won the conditional unique-key race.
                existing = Job.all_objects.get(
                    tenant=request.tenant,
                    idempotency_key=key,
                    state__in=[Job.State.QUEUED, Job.State.RUNNING, Job.State.COMPLETED],
                )
        scan = Scan.all_objects.get(pk=existing.payload["scan_id"], tenant=request.tenant)
        if existing.dispatch_pending:
            from .tasks import publish_scan

            # Publication failure is recorded by publish_scan; it never turns a
            # committed submission into an HTTP 500 or loses the dispatch intent.
            transaction.on_commit(lambda: publish_scan(str(existing.id)))
        response = self.get_serializer(scan).data
        response["job"] = SERIALIZERS[Job](existing).data
        response["deduplicated"] = not created
        headers = self.get_success_headers(response)
        return Response(response, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK, headers=headers)


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
    "organizations": viewset_for(Organization),
    "workspaces": viewset_for(Workspace),
    "applications": viewset_for(Application),
    "memberships": viewset_for(Membership),
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
    "assessments": viewset_for(Assessment),
    "assessment-responses": AssessmentResponseViewSet,
    "assessment-evidence": viewset_for(AssessmentEvidence, immutable=True),
    "evidence": viewset_for(Evidence, immutable=True),
    "compliance-gaps": viewset_for(ComplianceGap),
    "risks": RiskViewSet,
    "risk-links": viewset_for(RiskLink),
    "risk-scores": viewset_for(RiskScore, immutable=True),
    "remediations": viewset_for(Remediation),
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
    if settings.S3_ENDPOINT_URL:
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
        GatewayPolicyError,
        ValueError,
    ) as exc:
        return Response({"error": type(exc).__name__, "detail": str(exc)}, status=400)
