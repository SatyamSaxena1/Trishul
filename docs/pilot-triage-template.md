# Pilot triage review template

Use this template for each pilot triage review. Replace every placeholder before
the review, link the underlying dashboard or evidence, and record decisions in
the relevant issue tracker. Unless noted otherwise, compare the review window
with the immediately preceding window of the same length.

## Review header

| Field | Value |
| --- | --- |
| Review window (UTC) | `<start> - <end>` |
| Review date (UTC) | `<date>` |
| Facilitator | `<name>` |
| Participants | `<names and roles>` |
| Environment / release | `<environment and version>` |
| Metrics and logs | `<dashboard or query links>` |
| Previous review | `<link>` |

## 1. Completion rate against the 95% target

**Definition:** completion rate is `completed jobs / all terminal jobs * 100`.
Report recovered jobs separately and count them as completed only if their final
state and output passed the same validation as a first-attempt completion. Do not
include jobs that are still queued or running in the denominator; report those
as work in progress and identify stuck jobs below.

| Measure | Current window | Previous window | Change | Evidence |
| --- | ---: | ---: | ---: | --- |
| Terminal jobs | `<count>` | `<count>` | `<value>` | `<link>` |
| Validated completed jobs | `<count>` | `<count>` | `<value>` | `<link>` |
| Completion rate | `<percent>` | `<percent>` | `<points>` | `<link>` |
| Distance from 95% target | `<points above/below>` | `<points above/below>` | `<points>` | `<link>` |
| Non-terminal work in progress | `<count>` | `<count>` | `<value>` | `<link>` |

- Target met: `yes / no`
- Explanation for a miss or material change: `<analysis>`
- Corrective action, owner, and due date: `<action / owner / date, or none>`

## 2. Unsuccessful and unhealthy jobs

Use mutually exclusive final-state counts where possible. **Recovered** means a
job that failed or timed out on an earlier attempt and later completed with a
validated output. **Stuck** means a non-terminal job beyond its queue or runtime
SLO, including a stale lease. State the configured thresholds in the evidence.

| State | Count | Rate | Previous | Oldest / longest | Cause or cluster | Action / owner | Evidence |
| --- | ---: | ---: | ---: | --- | --- | --- | --- |
| Failed | `<n>` | `<%>` | `<n / %>` | `<duration>` | `<cause>` | `<action / owner>` | `<link>` |
| Rejected | `<n>` | `<%>` | `<n / %>` | `<duration>` | `<policy or cause>` | `<action / owner>` | `<link>` |
| Timed out | `<n>` | `<%>` | `<n / %>` | `<duration>` | `<stage or cause>` | `<action / owner>` | `<link>` |
| Recovered | `<n>` | `<%>` | `<n / %>` | `<attempts / duration>` | `<recovery path>` | `<action / owner>` | `<link>` |
| Stuck | `<n>` | `<% of WIP>` | `<n / %>` | `<age>` | `<queue or stage>` | `<action / owner>` | `<link>` |

- Job IDs needing individual follow-up: `<IDs and issue links, or none>`
- Repeat failures from the previous review: `<details, or none>`

## 3. Runtime and queue trends

Segment material changes by repository size, analyzer/language pack, tenant, and
worker pool so changes in workload mix are not mistaken for regressions.

| Signal | Current p50 | Current p95 | Previous p50 / p95 | SLO | Trend / interpretation | Evidence |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| End-to-end runtime | `<value>` | `<value>` | `<values>` | `<value>` | `<trend>` | `<link>` |
| Queue wait | `<value>` | `<value>` | `<values>` | `<value>` | `<trend>` | `<link>` |
| Analyzer runtime | `<value>` | `<value>` | `<values>` | `<value>` | `<trend>` | `<link>` |

| Queue health | Current peak | Previous peak | Current at review | Trend / action | Evidence |
| --- | ---: | ---: | ---: | --- | --- |
| Queue depth | `<n>` | `<n>` | `<n>` | `<trend / action>` | `<link>` |
| Oldest queued-job age | `<duration>` | `<duration>` | `<duration>` | `<trend / action>` | `<link>` |
| Active / available workers | `<n / n>` | `<n / n>` | `<n / n>` | `<trend / action>` | `<link>` |

## 4. New false-positive clusters

A cluster is a repeatable group sharing a rule, source pattern, framework, model,
or root cause. List clusters first observed in this window; do not hide them in
an aggregate precision number.

| Cluster / sample findings | First seen | Affected rule, pack, or model | Count / scope | Analyst impact | Hypothesis | Disposition / owner | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `<name / IDs>` | `<date>` | `<component>` | `<n / scope>` | `<impact>` | `<cause>` | `<defect, tune, monitor / owner>` | `<labels and examples>` |

- Sampling method and sample size: `<method / n>`
- Previously reported clusters that grew materially: `<details, or none>`

## 5. Analyst-blocking workflow friction

Record any workflow problem that prevents or materially delays an analyst from
starting a job, inspecting evidence, triaging a finding, exporting results, or
completing approval. Include workarounds; a workaround does not make a blocker
non-blocking.

| Workflow step | Users affected | Blocked time / frequency | Symptom | Workaround | Defect / owner | Evidence |
| --- | ---: | --- | --- | --- | --- | --- |
| `<step>` | `<n / roles>` | `<duration / frequency>` | `<description>` | `<workaround or none>` | `<issue / owner>` | `<recording, logs, or steps>` |

## 6. Security, isolation, backup, and data-loss incidents

Include confirmed incidents and near misses. Specifically review authorization
failures, tenant or job isolation, secret exposure, audit integrity, backup and
restore failures, and lost, corrupted, or unrecoverable data. Never paste secrets
or sensitive customer data into this review.

| Category | Incident / severity | Status | Scope and data affected | Containment / recovery | Follow-up / owner | Incident record |
| --- | --- | --- | --- | --- | --- | --- |
| Security | `<summary / severity, or none>` | `<status>` | `<scope>` | `<action>` | `<action / owner>` | `<link>` |
| Isolation | `<summary / severity, or none>` | `<status>` | `<scope>` | `<action>` | `<action / owner>` | `<link>` |
| Backup / restore | `<summary / severity, or none>` | `<status>` | `<scope>` | `<action>` | `<action / owner>` | `<link>` |
| Data loss / corruption | `<summary / severity, or none>` | `<status>` | `<scope>` | `<action>` | `<action / owner>` | `<link>` |

- Required escalation or notification completed: `<yes / no / not applicable; evidence>`
- Restore point and last successful restore exercise: `<timestamp / date / evidence>`

## 7. Capacity and disk pressure

| Resource | Current | Peak | Limit | Headroom | Forecast / exhaustion date | Action / owner | Evidence |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| CPU | `<value>` | `<value>` | `<value>` | `<value>` | `<forecast>` | `<action / owner>` | `<link>` |
| Memory | `<value>` | `<value>` | `<value>` | `<value>` | `<forecast>` | `<action / owner>` | `<link>` |
| Worker concurrency | `<value>` | `<value>` | `<value>` | `<value>` | `<forecast>` | `<action / owner>` | `<link>` |
| Database storage | `<value>` | `<value>` | `<value>` | `<value>` | `<forecast>` | `<action / owner>` | `<link>` |
| Job / local disk | `<value>` | `<value>` | `<value>` | `<value>` | `<forecast>` | `<action / owner>` | `<link>` |
| Object storage | `<value>` | `<value>` | `<value>` | `<value>` | `<forecast>` | `<action / owner>` | `<link>` |
| Backup storage | `<value>` | `<value>` | `<value>` | `<value>` | `<forecast>` | `<action / owner>` | `<link>` |

- Disk-pressure alerts, cleanup failures, or unexpected growth: `<details, or none>`
- Capacity change required before the next review: `<change / owner / date, or none>`

## 8. Open acceptance blockers

List every unresolved defect or operational condition that prevents a pilot
acceptance criterion from being demonstrated. Link the criterion and the defect;
do not substitute an aggregate count.

| Acceptance criterion | Blocker | Severity | Owner | Target release | Exit evidence | Status / next step |
| --- | --- | --- | --- | --- | --- | --- |
| `<criterion / link>` | `<issue / link>` | `<severity>` | `<owner>` | `<release>` | `<required proof>` | `<status / action / date>` |

- New blockers this window: `<issues, or none>`
- Blockers closed this window and validation evidence: `<issues and links, or none>`
- Acceptance recommendation: `proceed / proceed with conditions / do not proceed`
- Conditions or rationale: `<details>`

## Defect acceptance gate

A report may be accepted into the pilot defect queue only when it is reproducible
or has sufficient diagnostic evidence and **all** fields below are populated.
Incomplete reports remain in intake and must not be counted as accepted defects.

| Required field | Entry |
| --- | --- |
| Defect and concise impact | `<issue / impact>` |
| Severity | `<defined severity and rationale>` |
| Owner | `<one accountable person or team>` |
| Target release | `<named release; not "TBD">` |
| Reproduction evidence | `<steps, job/finding IDs, timestamps, logs, screenshots, or diagnostic evidence>` |
| Regression-test expectation | `<automated test to add, or explicit rationale and alternative validation>` |
| Rollback impact | `<user/data/schema/operational impact and rollback trigger, or "none" with rationale>` |

- Defect intake decision: `accepted / needs evidence / duplicate / backlog`
- Decision owner and date: `<name / date>`
- Issue link: `<link>`

## Scope disposition and closeout

Feature requests and non-blocking enhancements are out of pilot defect scope.
Move them to the **post-pilot backlog**, link the backlog item, and remove them
from acceptance-blocker and pilot-defect counts. Do not use the backlog to defer
security, data-loss, isolation, analyst-blocking, or acceptance-blocking defects.

| Intake item | Classification | Destination / link | Decision owner | Rationale |
| --- | --- | --- | --- | --- |
| `<item>` | `feature request / non-blocking enhancement` | `post-pilot backlog / <link>` | `<owner>` | `<reason>` |

### Decisions and actions

| Decision or action | Owner | Due date / target release | Tracking link | Status |
| --- | --- | --- | --- | --- |
| `<action>` | `<owner>` | `<date or release>` | `<link>` | `<status>` |

- Review record approved by: `<name / role / date>`
- Next review: `<date and time>`
