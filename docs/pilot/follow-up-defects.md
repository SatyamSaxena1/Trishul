# Pilot golden-path follow-up defects

This register is intentionally free of customer/repository identifiers and evidence. Add or update a
row as soon as a required baseline step cannot complete or cannot be measured reliably. The detailed
ticket may live in the approved tracker; only a non-sensitive reference belongs here.

| ID | Priority | Status | Blocked step | Aggregate impact | Owner | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| PILOT-001 | P1 | Open | Analysis job completion and runtime measurement | Successful scan jobs are created as `queued`, but the worker does not transition the corresponding job to `running` or `completed`; submitted/completed job totals and job runtime cannot be reliably reconciled. | Backend | On scan execution, the associated job atomically records running/lease/attempt state and then completed terminal state; failure remains terminal with a sanitized code; automated tests cover success, failure, retry/stale lease, and reconciliation; a pilot rerun reconciles all job totals without database edits. |

## New defect template

| ID | Priority | Status | Blocked step | Aggregate impact | Owner | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| PILOT-NNN | P0/P1/P2/P3 | Open | Upload / validation / analysis / review / risk | Number of jobs or findings affected; no identifiers or evidence | Team/role | Observable behavior and rerun proof required to close |

Defects remain open until the acceptance criteria pass and a subsequent controlled run verifies the
golden path. Do not mark a defect closed solely because an undocumented workaround exists.
