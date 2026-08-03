# Design-partner sign-off template

Use this template to document whether a design-partner evaluation is ready to
advance. Complete it only after the relevant evidence has been reviewed; a
successful demonstration by itself is not acceptance.

> **Sensitive-record handling:** Do not commit a completed or signed copy of
> this template, signatures, personal contact details, customer evidence,
> repository names, findings, credentials, tenant data, or acceptance rationale
> to the source repository. Store the authoritative completed record and its
> attachments in the approved customer-record system. The source repository may
> contain this blank template only. If a work item needs to refer to the signed
> record, use the customer-record system's non-sensitive record identifier and
> access-controlled link, subject to customer policy.

## Evaluation record

| Field | Value |
| --- | --- |
| Customer-record system record ID | `[record ID — no customer data]` |
| Access-controlled record link | `[link, if policy permits]` |
| Design partner | `[record in customer-record system]` |
| Product/release and immutable version | `[version, image digest, or release ID]` |
| Evaluation environment | `[environment identifier and deployment profile]` |
| Tenant(s) tested | `[non-sensitive identifiers]` |
| Evaluation period | `[YYYY-MM-DD through YYYY-MM-DD]` |
| Evidence package location | `[access-controlled link]` |
| Template version | `[commit or document version]` |
| Record owner | `[name/role]` |

## Decision vocabulary

Choose exactly one decision for every evaluation area and for every final
approver:

- **Acceptance** — the agreed criteria are met and no condition is required.
- **Conditional acceptance** — use may proceed only under explicitly recorded,
  time-bound conditions. Every condition must have an owner, due date, and
  verification method.
- **Rejection** — the criteria are not met or the residual risk is unacceptable.
  Record what must change before reevaluation.

Do not treat silence, an empty field, or an expired condition as acceptance.

## Evaluation areas

For each area, record the evidence reviewed, gaps or observations, and the
decision with a dated rationale. Put sensitive detail in the evidence package,
not in repository issues or commits.

### 1. Repository coverage

Confirm that the evaluated repository set, languages, frameworks, build forms,
generated/vendored-code exclusions, branches or revisions, and unsupported
content are explicitly inventoried. Compare analyzed files and skipped/error
counts with the agreed scope, and sample exclusions to ensure that material code
was not silently omitted.

| Field | Entry |
| --- | --- |
| Agreed scope and success criteria | `[scope/evidence reference]` |
| Coverage results and exclusions | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 2. Finding usefulness

Assess whether findings are understandable, actionable, correctly prioritized,
traceable to evidence, and useful in the partner's workflow. Review a
representative sample with intended users and record false-positive,
duplicate/noise, severity, remediation-guidance, and material false-negative
observations. Do not claim precision or recall beyond the sampled evidence.

| Field | Entry |
| --- | --- |
| Sample and success criteria | `[evidence reference]` |
| User feedback and measured results | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 3. Reliability

Review successful and failed run rates, deterministic/repeat-run behavior,
timeouts, queue and dependency failures, resource exhaustion, recovery, health
signals, and the integrity of partial or retried results. State the tested load,
duration, and failure-injection boundaries.

| Field | Entry |
| --- | --- |
| Reliability target and test profile | `[evidence reference]` |
| Results, failures, and recovery behavior | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 4. Security and tenant isolation

Confirm authentication and authorization behavior, role boundaries, tenant
scoping in application and database paths, object-storage separation, analyzer
isolation, network policy, secrets handling, auditability, export controls, and
abuse/failure cases. Include negative cross-tenant tests and an internal security
review; a functional happy-path test is insufficient.

| Field | Entry |
| --- | --- |
| Threat model and security criteria | `[evidence reference]` |
| Isolation/security test results and residual risks | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 5. Data handling

Document data classes and flows for source, findings, evidence, prompts/model
responses, logs, metrics, exports, backups, and support artifacts. Verify
approved storage and model endpoints, encryption, access, retention/deletion,
redaction, residency, subprocessors, telemetry behavior, and incident response
against the partner's requirements.

| Field | Entry |
| --- | --- |
| Approved data-flow/retention requirements | `[evidence reference]` |
| Validation results and exceptions | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 6. Installation and operations

Validate the supported deployment profile from documented prerequisites through
installation, configuration, identity bootstrap, health checks, observability,
alerting, routine maintenance, upgrade, troubleshooting, and support handoff.
Record the operator, elapsed effort, deviations, and any undocumented manual
steps.

| Field | Entry |
| --- | --- |
| Deployment profile and operational criteria | `[evidence reference]` |
| Installation/operations exercise results | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 7. Backup restoration

Perform a restoration exercise rather than relying only on backup creation.
Verify database and object data from the same checkpoint, encryption-key
availability, manifests/checksums, audit-chain integrity, restored release and
configuration compatibility, tenant isolation, authentication, readiness, and
agreed recovery objectives. Record measured recovery point and recovery time.

| Field | Entry |
| --- | --- |
| Recovery objectives and tested backup ID | `[evidence reference]` |
| Restore results, integrity checks, measured RPO/RTO | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 8. Rollback

Exercise or tabletop the documented rollback path for the evaluated release.
Confirm trigger and decision authority, artifact availability, schema
compatibility limits, configuration and secret recovery, data reconciliation,
verification checks, communications, and the point at which restore or a
forward fix is required instead of image rollback.

| Field | Entry |
| --- | --- |
| Rollback scenario and success criteria | `[evidence reference]` |
| Results, elapsed time, and restore/forward-fix boundary | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 9. Known limitations

List all limitations relevant to the evaluated use, including experimental
capabilities, unsupported languages/frameworks/deployments, scale boundaries,
model/provider constraints, coverage gaps, manual controls, and recovery or
rollback restrictions. Confirm that user-facing and operator documentation sets
appropriate expectations and that mitigations are workable.

| Field | Entry |
| --- | --- |
| Limitation register | `[evidence reference]` |
| Impact, mitigation, and communication assessment | `[evidence reference and summary]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

### 10. Unresolved non-blocking issues

Record issues that remain open but do not block the proposed use. For each,
include severity and impact, why it is non-blocking, compensating controls,
owner, target date, tracking reference, and the event that would make it a
blocker. Any issue without an accountable owner and review date is not eligible
for non-blocking classification.

| Issue/reference | Severity and impact | Non-blocking rationale and compensating control | Owner | Target/review date | Blocker trigger |
| --- | --- | --- | --- | --- | --- |
| `[ID]` | `[severity — impact]` | `[rationale — control]` | `[owner]` | `[YYYY-MM-DD]` | `[trigger]` |
| `[add rows or state None]` |  |  |  |  |  |

| Field | Entry |
| --- | --- |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale for the complete issue set]` |
| Conditions or required remediation | `[owner — action — due date — verification method, or None]` |

## Conditions and follow-up register

Consolidate every condition from the sections above. Conditional acceptance is
valid only while all listed controls remain in place and dates remain current.
Changing scope, release, architecture, data handling, tenant model, or a material
assumption requires impact review and may require renewed sign-off.

| Condition ID | Area | Required action or compensating control | Owner | Due date | Verification evidence and reviewer | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `[C-01]` | `[area]` | `[action/control]` | `[owner]` | `[YYYY-MM-DD]` | `[evidence — reviewer]` | `[Open / Verified / Overdue]` |
| `[add rows or state None]` |  |  |  |  |  |  |

## Overall recommendation

| Field | Entry |
| --- | --- |
| Proposed use and boundaries | `[who may use what, where, and for which purpose]` |
| Overall recommendation | `[Acceptance / Conditional acceptance / Rejection]` |
| Recommendation date | `[YYYY-MM-DD]` |
| Rationale | `[evidence-based rationale, including residual risk]` |
| Conditions | `[condition IDs, or None]` |
| Reevaluation trigger/date | `[trigger and YYYY-MM-DD, or None]` |

## Required approvals

Each authorized representative records an independent decision. All three
approvals are required; the overall result cannot be more permissive than the
most restrictive approval. A rejection blocks sign-off. A conditional
acceptance makes the overall result conditional and must cite active condition
IDs. Electronic approvals must be captured using the approved
customer-record-system workflow.

### Authorized design-partner representative

| Field | Entry |
| --- | --- |
| Name and title | `[record in customer-record system]` |
| Authority/basis to accept | `[role or authorization reference]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale and accepted residual risk]` |
| Condition IDs | `[IDs, or None]` |
| Signature/approval audit record | `[customer-record system audit reference]` |

### Internal product owner

| Field | Entry |
| --- | --- |
| Name and title | `[record in customer-record system]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale and product/use boundaries]` |
| Condition IDs | `[IDs, or None]` |
| Signature/approval audit record | `[customer-record system audit reference]` |

### Internal security owner

| Field | Entry |
| --- | --- |
| Name and title | `[record in customer-record system]` |
| Decision | `[Acceptance / Conditional acceptance / Rejection]` |
| Dated rationale | `[YYYY-MM-DD — rationale and residual-risk determination]` |
| Condition IDs | `[IDs, or None]` |
| Signature/approval audit record | `[customer-record system audit reference]` |

## Closure

| Field | Entry |
| --- | --- |
| Effective overall result | `[Acceptance / Conditional acceptance / Rejection]` |
| Effective date | `[YYYY-MM-DD]` |
| Approval completeness verified by | `[name/role and YYYY-MM-DD]` |
| Conditions next reviewed | `[YYYY-MM-DD, or None]` |
| Supersedes record | `[record ID, or None]` |
| Authoritative signed-record location | `[approved customer-record system record ID/link]` |
