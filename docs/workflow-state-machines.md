# Workflow state machines

Trishul keeps current state on each domain row and uses PostgreSQL as the state authority. The `workflow` Django app is deliberately small: frozen Python machine definitions, one transactional transition function, and one immutable tenant-scoped history table. Celery remains the asynchronous runner; there is no separate workflow service.

## Implemented machines

| Machine | State field | Transition callers |
|---|---|---|
| `deployment_evaluation` v1 | `EvaluationRun.state` | evaluation worker, evaluator, lease reconciler |
| `engagement` v1 | `Engagement.status` | engagement transition API and active-on-create compatibility path |
| `organisation_control` v1 | `OrganisationControl.status` | evidence synchronization, auditor verdict, manager/lead unlock, control transition API |

Every transition locks the entity with `select_for_update()`, checks its optimistic `version`, validates the event, writes the new state, appends a hash-chained `AuditEvent`, and inserts an immutable `WorkflowTransition` in one database transaction. An idempotency key is unique per tenant, machine, and entity. Timeline metadata is allow-listed by internal callers; artifact bodies, secrets, object keys, prompts, and exception text must never be stored there.

## API contract

Engagements and organisation controls expose:

- `GET .../{id}/available-transitions/`
- `GET .../{id}/timeline/`
- `POST .../{id}/transition/`

Evaluation runs expose the same endpoints, but their transition POST accepts only `cancel`; worker-controlled phase changes are never writable through REST. Transition POSTs require `If-Match: <current version>`. Missing versions return 428, stale versions return 412, and an invalid transition returns 409. Send `Idempotency-Key` when a client may retry. Ordinary serializers treat lifecycle fields as read-only.

Closing or revoking an engagement requires a reason. Auditor verdicts run in the auditee tenant context while retaining the firm actor tenant and engagement ID. A final control can be reopened only by an audit manager or lead auditor with a reason.

## Upgrade

1. Back up PostgreSQL and verify the current audit chain.
2. Deploy migrations before workers and API processes.
3. `workflow.0001` creates the ledger, `0002` forces RLS and adds the immutable trigger, and `0003` records one `migration_imported` checkpoint for each existing engagement, organisation control, and evaluation run.
4. The import records only the current known state; it does not invent history.
5. Deploy API and workers from the same release so all three machine definitions have version 1.
6. Run the full test suite and `scripts/verify_postgres_security.py` with owner and non-owner application DSNs.

## Rollback

Do not reverse or delete the workflow ledger after it has received production history. Disable transition POSTs and new evaluation submission, stop effect-producing workers, and leave entity/timeline reads available. The previous application may be deployed only if it accepts the additive tables and current state values. For an incompatible database failure, restore the matching PostgreSQL backup and object-storage checkpoint into a clean environment.

## Deliberately deferred

Task, risk/acceptance, evidence-ingestion, waiver, and policy machines remain direct lifecycle paths and are visible in the state-mutation inventory. Add each only with its end-to-end product workflow; the current three-machine slice does not justify Temporal, Camunda, `django-fsm`, a plugin registry, or another queue.
