"""Deployment Assurance REST API.

Follows the conventions already established in ``core.views``: tenant resolution
on every request, explicit permission identifiers, application-scope
restrictions, ``If-Match`` optimistic concurrency with 428/412, immutable
resources, and an audit event for every state change.

It deliberately does *not* subclass ``core.views.TenantModelViewSet``. That
class routes authorization through module-level tables in ``core`` keyed by
model; extending them would mean editing ``core`` every time this module grows a
resource. The shared behaviour is small enough to restate, and the module
boundary is worth more than the saved lines.
"""

import hashlib
import hmac
import logging

from django.db import transaction
from django.utils import timezone
from rest_framework import exceptions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from core.entitlements import EntitlementDenied, enforce, record_usage
from core.models import AuditEvent
from core.security import ServicePrincipal, has_permission, resolve_tenant
from workflow.engine import InvalidTransition, StaleTransition, transition
from workflow.machines import EVALUATION
from workflow.models import WorkflowTransition

from . import decisions
from . import permissions as perms
from .limits import MAX_ARTIFACT_BYTES, ArtifactTooLarge
from .models import (
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
)
from .normalizers import SUPPORTED_SOURCE_TYPES
from .oscal import assessment_results
from .serializers import (
    SERIALIZERS,
    EvaluationRequestSerializer,
    SnapshotUploadSerializer,
    WaiverDecisionSerializer,
)

logger = logging.getLogger(__name__)


class PreconditionRequired(exceptions.APIException):
    status_code = 428
    default_detail = "If-Match with the current resource version is required."
    default_code = "precondition_required"


class PreconditionFailed(exceptions.APIException):
    status_code = 412
    default_detail = "Resource version does not match."
    default_code = "precondition_failed"


class PayloadTooLarge(exceptions.APIException):
    status_code = 413
    default_detail = "The submitted artifact exceeds the permitted size."
    default_code = "artifact_too_large"


class TransitionConflict(exceptions.APIException):
    status_code = 409
    default_detail = "The requested lifecycle transition is not available."
    default_code = "invalid_transition"


class AssuranceViewSet(viewsets.ModelViewSet):
    """Base viewset carrying the module's tenancy and authorization contract."""

    model = None
    read_permission = ""
    write_permission = ""
    immutable = False
    #: ORM path from this model to ``core.Application``, for scope restriction.
    application_path = ""
    #: Custom-action name -> required permission. Without this, a custom action
    #: would inherit the viewset's generic write permission, which is both
    #: wrong (approving is not requesting) and dangerous in the other
    #: direction (a broad write grant would unlock a narrow privileged action).
    action_permissions: dict[str, str] = {}

    def perform_authentication(self, request):
        super().perform_authentication(request)
        if not hasattr(request, "tenant"):
            resolve_tenant(request)

    def get_serializer_class(self):
        return SERIALIZERS[self.model]

    def get_queryset(self):
        queryset = self.model.objects.all().order_by("-created_at")
        restrictions = self._application_restrictions()
        if restrictions and self.application_path:
            return queryset.filter(**{f"{self.application_path}__in": restrictions})
        return queryset

    def _application_restrictions(self):
        if isinstance(self.request.user, ServicePrincipal):
            return self.request.user.account.application_ids
        return self.request.membership.application_ids if self.request.membership else []

    def get_required_permission(self):
        action = getattr(self, "action", None)
        if action in self.action_permissions:
            return self.action_permissions[action]
        if self.request.method in {"GET", "HEAD", "OPTIONS"}:
            return self.read_permission
        return self.write_permission

    def check_permissions(self, request):
        super().check_permissions(request)
        # Let an unsupported method fall through to DRF's 405. Answering 403
        # here would imply the method exists but is merely forbidden.
        if request.method.lower() not in self.http_method_names:
            return
        required = self.get_required_permission()
        if not required:
            raise exceptions.PermissionDenied("This operation is not available on this resource.")
        self._require(required)

    def _require(self, permission):
        """Check a grant, then apply the human-only boundary on top of it.

        A service account holding a human-only scope is a token-issuance
        mistake; refusing it here means the mistake cannot be exploited.
        """
        if permission in perms.HUMAN_ONLY and isinstance(self.request.user, ServicePrincipal):
            raise exceptions.PermissionDenied("A human user is required for this operation.")
        if not has_permission(self.request, permission):
            raise exceptions.PermissionDenied("Permission is not granted for this operation.")

    def _actor(self):
        if isinstance(self.request.user, ServicePrincipal):
            return "service_account", str(self.request.user.id)
        return "user", str(self.request.user.id)

    def _audit(self, action_name, instance, **details):
        actor_type, actor_id = self._actor()
        AuditEvent.append(
            tenant=self.request.tenant,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action_name,
            resource_type=instance._meta.label_lower,
            resource_id=instance.pk,
            details={"version": getattr(instance, "version", 1), **details},
        )

    def _check_application_scope(self, application_id):
        restrictions = self._application_restrictions()
        if restrictions and str(application_id) not in restrictions:
            raise exceptions.PermissionDenied("Application scope does not permit this operation.")

    def _match_version(self, instance):
        supplied = self.request.headers.get("If-Match")
        if supplied is None:
            raise PreconditionRequired()
        if supplied.strip('W/"') != str(instance.version):
            raise PreconditionFailed()

    def perform_create(self, serializer):
        instance = serializer.save(tenant=self.request.tenant)
        self._audit(f"{self.model._meta.model_name}.created", instance)

    def perform_update(self, serializer):
        if self.immutable:
            raise exceptions.MethodNotAllowed(self.request.method, "Resource is immutable.")
        with transaction.atomic():
            instance = self.model.objects.select_for_update().get(pk=serializer.instance.pk)
            self._match_version(instance)
            serializer.instance = instance
            updated = serializer.save(version=instance.version + 1)
            self._audit(f"{self.model._meta.model_name}.updated", updated)

    def perform_destroy(self, instance):
        if self.immutable:
            raise exceptions.MethodNotAllowed(self.request.method, "Resource is immutable.")
        with transaction.atomic():
            locked = self.model.objects.select_for_update().get(pk=instance.pk)
            self._match_version(locked)
            self._audit(f"{self.model._meta.model_name}.deleted", locked)
            locked.delete()


class ReadOnlyAssuranceViewSet(AssuranceViewSet):
    http_method_names = ["get", "head", "options"]
    immutable = True


class DeploymentTargetViewSet(AssuranceViewSet):
    model = DeploymentTarget
    read_permission = perms.TARGET_READ
    write_permission = perms.TARGET_WRITE
    application_path = "application_id"

    def perform_create(self, serializer):
        self._check_application_scope(serializer.validated_data["application"].id)
        super().perform_create(serializer)

    def perform_destroy(self, instance):
        """Targets are retired, never deleted, while evidence references them."""
        raise exceptions.MethodNotAllowed("DELETE", "Set state to decommissioned; retained evidence forbids deletion.")


class DeploymentSnapshotViewSet(AssuranceViewSet):
    model = DeploymentSnapshot
    read_permission = perms.SNAPSHOT_READ
    write_permission = perms.SNAPSHOT_SUBMIT
    application_path = "target__application_id"
    http_method_names = ["get", "post", "head", "options"]
    action_permissions = {"evaluations": perms.EVALUATION_CREATE}

    def create(self, request, *args, **kwargs):
        """Accept a deployment artifact, hash it, and store it immutably.

        The artifact is read once into memory under the ingestion bound, hashed
        server-side, and written to the object store before the row is created.
        A client-supplied hash is never trusted.
        """
        from . import evidence as evidence_module

        serializer = SnapshotUploadSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        target = data["target"]
        self._check_application_scope(target.application_id)

        source_type = data["source_type"]
        if source_type not in SUPPORTED_SOURCE_TYPES:
            raise exceptions.ValidationError({"source_type": "No normalizer is installed for this source type."})

        uploaded = data["artifact"]
        if uploaded.size > MAX_ARTIFACT_BYTES:
            raise PayloadTooLarge()
        try:
            enforce(request.tenant, "evidence_bytes", quantity=uploaded.size)
        except EntitlementDenied as exc:
            raise exceptions.PermissionDenied(str(exc)) from exc
        payload = uploaded.read()
        if len(payload) > MAX_ARTIFACT_BYTES:
            raise PayloadTooLarge()
        digest = hashlib.sha256(payload).hexdigest()

        actor_type, actor_id = self._actor()
        snapshot = DeploymentSnapshot.all_objects.create(
            tenant=request.tenant,
            target=target,
            source_type=source_type,
            source_reference=data.get("source_reference", "")[:400],
            source_revision=data.get("source_revision", "")[:120],
            artifact_object_key="pending",
            artifact_sha256=digest,
            artifact_size=len(payload),
            media_type=uploaded.content_type or "application/octet-stream",
            collected_by_type=(
                DeploymentSnapshot.CollectorType.SERVICE_ACCOUNT
                if actor_type == "service_account"
                else DeploymentSnapshot.CollectorType.USER
            ),
            collected_by_id=actor_id,
            metadata=data.get("metadata") or {},
            ingestion_state=DeploymentSnapshot.IngestionState.VALIDATING,
        )
        try:
            artifact = evidence_module.record(
                tenant=request.tenant,
                target=target,
                snapshot=snapshot,
                role=EvidenceArtifact.Role.SOURCE_ARTIFACT,
                payload=payload,
                media_type=snapshot.media_type,
                source={
                    "type": "api_upload",
                    "actor_type": actor_type,
                    "source_reference": snapshot.source_reference,
                    "source_revision": snapshot.source_revision,
                },
                run_id=str(snapshot.id),
                max_bytes=MAX_ARTIFACT_BYTES,
            )
        except ArtifactTooLarge as exc:
            DeploymentSnapshot.all_objects.filter(pk=snapshot.pk).update(
                ingestion_state=DeploymentSnapshot.IngestionState.REJECTED
            )
            raise PayloadTooLarge() from exc
        except Exception:
            logger.exception("Snapshot artifact storage failed for %s", snapshot.id)
            DeploymentSnapshot.all_objects.filter(pk=snapshot.pk).update(
                ingestion_state=DeploymentSnapshot.IngestionState.REJECTED
            )
            raise

        snapshot.artifact_object_key = artifact.object_key
        snapshot.ingestion_state = DeploymentSnapshot.IngestionState.READY
        snapshot.finalized_at = timezone.now()
        snapshot.version += 1
        snapshot.save(update_fields=["artifact_object_key", "ingestion_state", "finalized_at", "version", "updated_at"])
        self._audit(
            "deployment_snapshot.submitted",
            snapshot,
            artifact_sha256=digest,
            source_type=source_type,
            size_bytes=len(payload),
        )
        record_usage(
            request.tenant,
            "evidence_bytes",
            len(payload),
            source_type="deployment_assurance.deploymentsnapshot",
            source_id=snapshot.id,
            idempotency_key=f"snapshot:{snapshot.id}",
        )
        return Response(SERIALIZERS[DeploymentSnapshot](snapshot).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="evaluations")
    def evaluations(self, request, pk=None):
        """Queue an evaluation of this snapshot and return 202 with its id."""
        from .tasks import dispatch_evaluation

        snapshot = self.get_object()
        if not snapshot.is_ready:
            raise exceptions.ValidationError({"snapshot": "The snapshot is not finalized and cannot be evaluated."})

        serializer = EvaluationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        profile = (
            data.get("policy_profile") or PolicyProfile.objects.filter(tenant=request.tenant, is_default=True).first()
        )
        if profile is None:
            raise exceptions.ValidationError(
                {"policy_profile": "No policy profile is assigned to this tenant. Run bootstrap_assurance."}
            )
        if snapshot.target.policy_profile_id and not data.get("policy_profile"):
            profile = snapshot.target.policy_profile

        idempotency_key = (request.headers.get("Idempotency-Key") or "")[:200]
        if idempotency_key:
            existing = EvaluationRun.objects.filter(tenant=request.tenant, idempotency_key=idempotency_key).first()
            if existing:
                # Replaying the same key returns the original run rather than
                # starting a second evaluation of the same artifact.
                return Response(_run_accepted(existing), status=status.HTTP_202_ACCEPTED)

        try:
            enforce(request.tenant, "deployment_evaluations")
        except EntitlementDenied as exc:
            raise exceptions.PermissionDenied(str(exc)) from exc

        actor_type, actor_id = self._actor()
        run = EvaluationRun.all_objects.create(
            tenant=request.tenant,
            snapshot=snapshot,
            target=snapshot.target,
            policy_pack=profile.policy_pack,
            policy_profile=profile,
            trigger=data["trigger"],
            idempotency_key=idempotency_key,
            requested_by_type=(
                DeploymentSnapshot.CollectorType.SERVICE_ACCOUNT
                if actor_type == "service_account"
                else DeploymentSnapshot.CollectorType.USER
            ),
            requested_by_id=actor_id,
            context=data.get("context") or {},
            parameters=data.get("parameters") or {},
        )
        self._audit("deployment_evaluation.requested", run, snapshot_id=str(snapshot.id), trigger=run.trigger)
        record_usage(
            request.tenant,
            "deployment_evaluations",
            1,
            source_type="deployment_assurance.evaluationrun",
            source_id=run.id,
            idempotency_key=f"evaluation:{run.id}",
        )
        transaction.on_commit(lambda: dispatch_evaluation(str(request.tenant.id), str(run.id)))
        return Response(_run_accepted(run), status=status.HTTP_202_ACCEPTED)


def _run_accepted(run: EvaluationRun) -> dict:
    return {
        "evaluation_run_id": str(run.id),
        "state": run.state,
        "status_url": f"/api/v1/assurance/evaluation-runs/{run.id}/",
        "correlation_id": str(run.correlation_id),
    }


class EvaluationRunViewSet(ReadOnlyAssuranceViewSet):
    model = EvaluationRun
    read_permission = perms.EVALUATION_READ
    application_path = "target__application_id"
    http_method_names = ["get", "post", "head", "options"]
    action_permissions = {
        "create": perms.EVALUATION_CREATE,
        "decision": perms.DECISION_READ,
        "oscal_results": perms.DECISION_READ,
        "available_transitions": perms.EVALUATION_READ,
        "timeline": perms.EVALUATION_READ,
        "transition": perms.EVALUATION_CREATE,
    }

    def create(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed("POST", "Create evaluations from a finalized snapshot.")

    @action(detail=True, methods=["get"], url_path="available-transitions")
    def available_transitions(self, request, pk=None):
        run = self.get_object()
        events = [event for event in EVALUATION.available_events(run.state) if event == "cancel"]
        return Response({"state": run.state, "version": run.version, "events": events})

    @action(detail=True, methods=["post"])
    def transition(self, request, pk=None):
        run = self.get_object()
        idempotency_key = request.headers.get("Idempotency-Key", "")
        if idempotency_key and WorkflowTransition.objects.filter(
            machine=EVALUATION.name,
            entity_id=run.id,
            event="cancel",
            idempotency_key=idempotency_key,
        ).exists():
            run.refresh_from_db()
            return Response(SERIALIZERS[EvaluationRun](run).data)
        self._match_version(run)
        if request.data.get("event") != "cancel":
            raise TransitionConflict()

        def cancelled(entity):
            entity.completed_at = timezone.now()
            entity.lease_expires_at = None
            return ("completed_at", "lease_expires_at")

        actor_type, actor_id = self._actor()
        try:
            result = transition(
                model=EvaluationRun,
                entity_id=run.id,
                machine=EVALUATION,
                event="cancel",
                tenant=request.tenant,
                actor_type=actor_type,
                actor_id=actor_id,
                actor_tenant=request.tenant,
                expected_version=run.version,
                reason=str(request.data.get("reason", "")).strip(),
                idempotency_key=idempotency_key,
                mutate=cancelled,
            )
        except StaleTransition as exc:
            raise PreconditionFailed() from exc
        except InvalidTransition as exc:
            raise TransitionConflict() from exc
        return Response(SERIALIZERS[EvaluationRun](result.entity).data)

    @action(detail=True, methods=["get"])
    def timeline(self, request, pk=None):
        run = self.get_object()
        rows = WorkflowTransition.objects.filter(machine=EVALUATION.name, entity_id=run.id)
        return Response(
            [
                {
                    "id": row.id,
                    "event": row.event,
                    "from_state": row.from_state,
                    "to_state": row.to_state,
                    "actor_type": row.actor_type,
                    "actor_id": row.actor_id,
                    "reason_code": row.reason_code,
                    "machine_version": row.machine_version,
                    "entity_version": row.entity_version_after,
                    "occurred_at": row.created_at,
                }
                for row in rows
            ]
        )

    @action(detail=True, methods=["get"])
    def results(self, request, pk=None):
        run = self.get_object()
        queryset = ControlResult.objects.filter(evaluation_run=run).order_by("resource_type", "resource_id", "id")
        outcome = request.query_params.get("outcome")
        if outcome:
            queryset = queryset.filter(outcome=outcome)
        page = self.paginate_queryset(queryset)
        serializer = SERIALIZERS[ControlResult](page if page is not None else queryset, many=True)
        return self.get_paginated_response(serializer.data) if page is not None else Response(serializer.data)

    @action(detail=True, methods=["get"])
    def decision(self, request, pk=None):
        run = self.get_object()
        decision = DeploymentDecision.objects.filter(evaluation_run=run).first()
        if decision is None:
            # 409 rather than 404: the run exists, the decision is not yet made.
            return Response(
                {
                    "type": "urn:trishul:deployment-assurance:decision-pending",
                    "title": "The evaluation has not produced a decision yet.",
                    "status": 409,
                    "code": "DECISION_PENDING",
                    "state": run.state,
                },
                status=status.HTTP_409_CONFLICT,
                content_type="application/problem+json",
            )
        results = list(ControlResult.objects.filter(evaluation_run=run))
        outcome = decisions.decide(
            profile=decisions.TargetProfile.from_target(run.target),
            results=results,
            thresholds=decision.threshold_profile,
            risk_total=decision.risk_score,
            had_error=any(result.outcome == "error" for result in results),
        )
        expected = decisions.decision_hash(run=run, outcome=outcome, thresholds=decision.threshold_profile)
        payload = SERIALIZERS[DeploymentDecision](decision).data
        payload["integrity_verified"] = hmac.compare_digest(expected, decision.decision_hash)
        return Response(payload)

    @action(detail=True, methods=["get"], url_path="oscal-results")
    def oscal_results(self, request, pk=None):
        """Export the run as an OSCAL Assessment Results document.

        The portable, standards-based view of the same decision. Trishul's
        relational schema stays authoritative; this is the interchange format.
        """
        run = self.get_object()
        if run.state != EvaluationRun.State.COMPLETED:
            raise exceptions.ValidationError({"state": "Only a completed run can be exported."})
        return Response(assessment_results(run))


class DeploymentDecisionViewSet(ReadOnlyAssuranceViewSet):
    model = DeploymentDecision
    read_permission = perms.DECISION_READ
    application_path = "target__application_id"


class ControlResultViewSet(ReadOnlyAssuranceViewSet):
    model = ControlResult
    read_permission = perms.EVALUATION_READ
    application_path = "evaluation_run__target__application_id"


class EvidenceArtifactViewSet(ReadOnlyAssuranceViewSet):
    model = EvidenceArtifact
    read_permission = perms.EVIDENCE_READ
    application_path = "target__application_id"


class DriftEventViewSet(ReadOnlyAssuranceViewSet):
    model = DriftEvent
    read_permission = perms.DRIFT_READ
    application_path = "target__application_id"


class PolicyPackViewSet(ReadOnlyAssuranceViewSet):
    model = PolicyPack
    read_permission = perms.POLICY_READ


class PolicyRuleViewSet(ReadOnlyAssuranceViewSet):
    model = PolicyRule
    read_permission = perms.POLICY_READ


class PolicyProfileViewSet(AssuranceViewSet):
    model = PolicyProfile
    read_permission = perms.POLICY_READ
    write_permission = perms.POLICY_MANAGE


class DecisionThresholdProfileViewSet(AssuranceViewSet):
    model = DecisionThresholdProfile
    read_permission = perms.POLICY_READ
    write_permission = perms.POLICY_MANAGE


class ExceptionWaiverViewSet(AssuranceViewSet):
    model = ExceptionWaiver
    read_permission = perms.EVALUATION_READ
    write_permission = perms.EXCEPTION_REQUEST
    application_path = "target__application_id"
    http_method_names = ["get", "post", "head", "options"]
    action_permissions = {"approve": perms.EXCEPTION_APPROVE}

    def perform_create(self, serializer):
        self._check_application_scope(serializer.validated_data["target"].application_id)
        waiver = serializer.save(
            tenant=self.request.tenant,
            requested_by=self.request.user,
            status=ExceptionWaiver.Status.REQUESTED,
        )
        self._audit(
            "deployment_exception.requested",
            waiver,
            rule=waiver.policy_rule.stable_key,
            expires_at=waiver.expires_at.isoformat(),
        )

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        """Record an independent approval or rejection.

        Self-approval is refused here as well as in ``ExceptionWaiver.clean``:
        the model guards the data, the view guards the request, and neither
        relies on the other being present.
        """
        serializer = WaiverDecisionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        waiver = self.get_object()
        if waiver.status != ExceptionWaiver.Status.REQUESTED:
            raise exceptions.ValidationError({"status": f"The waiver is already {waiver.status}."})
        if waiver.requested_by_id == request.user.id:
            raise exceptions.ValidationError({"approver": "Requesters cannot approve their own waiver."})

        approved = serializer.validated_data["decision"] == "approved"
        waiver.status = ExceptionWaiver.Status.APPROVED if approved else ExceptionWaiver.Status.REJECTED
        waiver.approved_by = request.user
        waiver.decided_at = timezone.now()
        waiver.decision_reason = serializer.validated_data["reason"]
        waiver.version += 1
        waiver.save(update_fields=["status", "approved_by", "decided_at", "decision_reason", "version", "updated_at"])
        self._audit(
            "deployment_exception.decided",
            waiver,
            decision=waiver.status,
            rule=waiver.policy_rule.stable_key,
            expires_at=waiver.expires_at.isoformat(),
        )
        return Response(SERIALIZERS[ExceptionWaiver](waiver).data)


ASSURANCE_VIEWSETS = {
    "deployment-targets": DeploymentTargetViewSet,
    "deployment-snapshots": DeploymentSnapshotViewSet,
    "evaluation-runs": EvaluationRunViewSet,
    "control-results": ControlResultViewSet,
    "deployment-decisions": DeploymentDecisionViewSet,
    "evidence-artifacts": EvidenceArtifactViewSet,
    "exception-waivers": ExceptionWaiverViewSet,
    "drift-events": DriftEventViewSet,
    "policy-packs": PolicyPackViewSet,
    "policy-rules": PolicyRuleViewSet,
    "policy-profiles": PolicyProfileViewSet,
    "threshold-profiles": DecisionThresholdProfileViewSet,
}
