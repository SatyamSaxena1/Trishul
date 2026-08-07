"""Celery tasks for Deployment Assurance.

Follows the lease-and-reconcile pattern already used by ``core.tasks``: state is
transitioned under a row lock, a lease bounds how long a run may be considered
in flight, and a periodic reconciler recovers runs whose worker died.

Every task establishes both the process-local tenant context and the PostgreSQL
``trishul.tenant_id`` setting before touching data. Without the second,
row-level security has nothing to match on and every query correctly returns
nothing — the failure mode is empty results, never another tenant's rows.
"""

import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from core.models import AuditEvent, Tenant
from core.tenancy import database_tenant_context, tenant_context
from workflow.engine import transition
from workflow.machines import EVALUATION

from .evaluation import EvaluationError, evaluate_snapshot
from .models import EvaluationRun, ExceptionWaiver

logger = logging.getLogger(__name__)


def _database_tenant(tenant_id):
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])


def dispatch_evaluation(tenant_id: str, run_id: str) -> None:
    """Queue on the existing analysis controller that owns the isolated runtime."""
    execute_evaluation.apply_async(args=[tenant_id, run_id], queue="analysis")


@shared_task(name="deployment_assurance.tasks.execute_evaluation", acks_late=True)
def execute_evaluation(tenant_id, run_id):
    with database_tenant_context(tenant_id):
        return _execute_evaluation(tenant_id, run_id)


def _execute_evaluation(tenant_id, run_id):
    """Run one evaluation to a terminal state.

    Claims the run under a lock so a duplicate delivery is a no-op, then
    evaluates outside the transaction: normalization and rule execution are the
    slow part and must not hold a row lock for their duration.
    """
    with transaction.atomic(), tenant_context(tenant_id):
        _database_tenant(tenant_id)
        run = (
            EvaluationRun.objects.select_for_update()
            .select_related("tenant", "target", "target__application", "snapshot", "policy_pack", "policy_profile")
            .get(pk=run_id)
        )
        if run.state != EvaluationRun.State.QUEUED:
            logger.info("Evaluation %s is already %s; ignoring duplicate delivery.", run_id, run.state)
            return

        def claim(entity):
            entity.started_at = timezone.now()
            entity.attempts += 1
            entity.lease_expires_at = timezone.now() + timedelta(seconds=settings.ASSURANCE_EVALUATION_LEASE_SECONDS)
            return ("started_at", "attempts", "lease_expires_at")

        run = transition(
            model=EvaluationRun,
            entity_id=run.id,
            machine=EVALUATION,
            event="start",
            tenant=run.tenant,
            actor_type="system",
            actor_id="deployment-assurance-worker",
            expected_version=run.version,
            mutate=claim,
        ).entity

    try:
        evaluate_snapshot(run)
    except EvaluationError as exc:
        _fail(tenant_id, run_id, str(exc).split(":", 1)[0][:80])
        # A rejected artifact is a client-side condition, not a worker fault.
        # Re-queueing it would fail identically, so the run ends here.
        logger.warning("Evaluation %s failed: %s", run_id, exc)
    except Exception as exc:
        logger.exception("Evaluation %s failed unexpectedly", run_id)
        _fail(tenant_id, run_id, type(exc).__name__[:80])
        raise


def _fail(tenant_id, run_id, error_code: str) -> None:
    """Mark a run failed and record it.

    A failed run has no decision. Consumers of the gate must treat the absence
    of an approved decision as "not approved" — this is why the CI check waits
    for a terminal decision rather than for the run merely to stop.
    """
    with transaction.atomic(), tenant_context(tenant_id):
        _database_tenant(tenant_id)
        run = EvaluationRun.objects.select_for_update().select_related("tenant", "target").get(pk=run_id)
        if run.state in EvaluationRun.TERMINAL_STATES:
            return

        def fail(entity):
            entity.error_code = error_code
            entity.completed_at = timezone.now()
            entity.lease_expires_at = None
            return ("error_code", "completed_at", "lease_expires_at")

        transition(
            model=EvaluationRun,
            entity_id=run.id,
            machine=EVALUATION,
            event="fail",
            tenant=run.tenant,
            actor_type="system",
            actor_id="deployment-assurance-worker",
            expected_version=run.version,
            reason_code=error_code,
            mutate=fail,
        )


@shared_task(name="deployment_assurance.tasks.reconcile_evaluations")
def reconcile_evaluations():
    """Recover runs whose worker died mid-flight.

    A run past its lease is either retried or failed. It is never left in a
    non-terminal state, because a CI check waiting on it would otherwise block
    until its own timeout with no explanation.
    """
    now = timezone.now()
    maximum = settings.ASSURANCE_MAX_EVALUATION_ATTEMPTS
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        with database_tenant_context(tenant_id), transaction.atomic():
            stale = EvaluationRun.objects.filter(
                state__in=[
                    EvaluationRun.State.NORMALIZING,
                    EvaluationRun.State.EVALUATING,
                    EvaluationRun.State.DECIDING,
                ],
                lease_expires_at__lt=now,
            ).select_for_update()
            for run in stale:
                retryable = run.attempts < maximum

                def expire_lease(entity, retryable=retryable):
                    entity.error_code = "lease_expired"
                    entity.lease_expires_at = None
                    if not retryable:
                        entity.completed_at = now
                    return ("error_code", "lease_expires_at", "completed_at")

                transition(
                    model=EvaluationRun,
                    entity_id=run.id,
                    machine=EVALUATION,
                    event="retry" if retryable else "fail",
                    tenant=run.tenant,
                    actor_type="system",
                    actor_id="deployment-assurance-reconciler",
                    expected_version=run.version,
                    reason_code="lease_expired",
                    mutate=expire_lease,
                )
                if retryable:
                    dispatch_evaluation(str(tenant_id), str(run.id))


@shared_task(name="deployment_assurance.tasks.expire_waivers")
def expire_waivers():
    """Expire approved waivers past their end date.

    Expiry restores the underlying blocker automatically. A waiver that had to
    be renewed by hand would, in practice, quietly become permanent.
    """
    now = timezone.now()
    for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
        with database_tenant_context(tenant_id), transaction.atomic():
            expired = ExceptionWaiver.objects.filter(
                status=ExceptionWaiver.Status.APPROVED, expires_at__lte=now
            ).select_for_update()
            for waiver in expired:
                waiver.status = ExceptionWaiver.Status.EXPIRED
                waiver.version += 1
                waiver.save(update_fields=["status", "version", "updated_at"])
                AuditEvent.append(
                    tenant=waiver.tenant,
                    actor_type="system",
                    actor_id="deployment-assurance",
                    action="deployment_exception.expired",
                    resource_type="deployment_assurance.exceptionwaiver",
                    resource_id=waiver.id,
                    details={"target_id": str(waiver.target_id), "rule_id": str(waiver.policy_rule_id)},
                )
