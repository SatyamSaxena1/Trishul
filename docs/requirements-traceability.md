# Concept-note requirements traceability

Baseline: evidence-intelligence and deterministic reuse lifecycle implementation on 10 August 2026.

Status is deliberately conservative: **implemented** means a usable, tested path;
**partial** means a schema, API, or narrow path exists; **planned** means no
material end-to-end implementation exists. This matrix is the release gate for
the GRC/TPRM programme, not a compliance attestation.

## Module delivery gate

| Requirement group | Status | Evidence | Required completion slice |
| --- | --- | --- | --- |
| M1 tenancy, identity and onboarding | Partial | Tenant/RLS/membership/engagement models, tenant-bound OIDC validation, one-time invitations, tenant-scoped SCIM Users provisioning and session-policy records | SAML interoperability/ACS, enforced session expiry, break-glass, custom roles and full persona journeys |
| M2 UCF and mappings | Partial | Versioned framework, requirement, UCO, mapping and delta models | Expert-approved ISO and DPDP packs, pack review/diff and instantiation |
| M3 scope and assets | Partial | Organisation, workspace and application records | Entities, locations, assets, ownership and applicability wizard |
| M4 evidence | Partial | Immutable evidence records, hashed upload, native text extraction, quality metadata, justified overrides and independently evaluated successors | PDF/OCR adapter and classification refinement |
| M5 evidence intelligence and reuse | Partial | Deterministic UCO candidate discovery, structured checks, immutable decisions and precise idempotent remediation | Optional retrieval/cited suggestion enhancements and production expert validation |
| M6 scoring | Partial | Weighted human-verdict framework score, configurable critical cap and evidence drill-down | Score snapshots and trends |
| M7 policy lifecycle | Planned | Deployment policy packs are not GRC policies | Authoring, approval, publication, attestation and expiry |
| M8 risk | Partial | Risk, remediation, task, acceptance and approval models | Appetite, treatment workflow, heat maps, KRI and role journeys |
| M9 TPRM | Planned | Vendor role/entitlement vocabulary only | Vendor, tiering, questionnaires, portal, campaigns, scoring and monitoring |
| M10 auditor workbench | Partial | Scoped engagements, composed control-review API, SOD verdicts, locks, change notifications and workflow history | Rich review screen, sampling, CAPA, QA and sealed report |
| M11 CISO portal | Partial | Pilot dashboard | Governance/risk/compliance portal, trends, forecasts and board packs |
| M12 workflow/reporting | Partial | Workflow engine, task/report records | Recurrence, notification, scheduling, rendering and distribution |
| integrations | Planned | Deployment normalizers only | AWS, Entra, Jira and GitHub collection paths |
| security and operations | Partial | RLS, audit chain and AWS recovery IaC | Applied/proven AWS controls, tenant KMS routing and timed drill |
| NFR and readiness | Planned | CI and basic health checks | Capacity, accessibility, SLO, privacy and browser evidence |

## Mandatory business rules

| ID | Rule | Current status | Acceptance evidence required |
| --- | --- | --- | --- |
| BR-53 | Control Owners can access only active assignments. | Implemented | API read/write denial after assignment removal and expiry. |
| BR-54 | Audit firms require a live, scoped engagement. | Implemented | Active, closed, revoked and expired engagement tests. |
| BR-55 | Evidence is never overwritten. | Implemented | Hashed upload, generated object keys, append-only version API, model tests and PostgreSQL trigger CI check. |
| BR-56 | Superseded evidence is independently revalidated on every link. | Implemented | Successor evaluation, new link and gap closure tests. |
| BR-57 | Locked controls are excluded from automatic propagation. | Implemented | Prior-verdict preservation and pending post-closure-change tests. |
| BR-58 | Auditor-closed controls become auditee read-only. | Implemented | Shared server-side write guard and auditee API denial test. |
| BR-59 | Unlock requires authority, reason and audit record. | Implemented | Reasoned manager-unlock and immutable-history tests. |
| BR-60 | Failed validation gives an actionable re-upload request. | Implemented | Structured delta/freshness/scope/attribute checks and fingerprinted gap/task lifecycle tests. |
| BR-61 | AI never issues final audit verdicts. | Partial | Suggestion-only AI contract and human-verdict integration tests. |
| BR-62 | AI decisions preserve provider/model/prompt/sources/confidence. | Partial | Immutable AI-run schema with citation and prompt tests. |
| BR-63 | Critical non-compliance caps framework score. | Implemented | Weighted score and configurable default-70% critical-cap test. |
| BR-64 | Not Applicable requires justification and is excluded from scoring. | Implemented | Model/API justification guards, human-review enforcement and score-exclusion test. |
| BR-65 | Below-threshold evidence requires a justified override. | Implemented | Authorized-human, mandatory-reason and immutable override tests. |
| BR-66 | Evidence uploader cannot verdict the same control. | Implemented | Uploader denial, independent-auditor success and denial-audit test. |
| BR-67 | Overdue policies reduce supported-control maturity. | Planned | Policy expiry scheduler and maturity recalculation test. |
| BR-68 | Unevidenced vendor claims receive reduced score credit. | Planned | Vendor scoring test. |
| BR-69 | Vendor disqualifiers override aggregate score. | Planned | Configurable disqualifier test. |
| BR-70 | Failed evidence collection alerts operators. | Planned | Connector failure, retry and alert test. |
| BR-71 | Tenant scoping is enforced for every query. | Partial | Static CI check plus PostgreSQL forced-RLS integration suite. |
| BR-72 | Every score drills down to an artefact. | Implemented | Requirement/control/verdict/evaluation/evidence-version contribution test. |

## Completion rule

No module is marked implemented until its required role journey, negative
authorization cases, immutable audit history, PostgreSQL RLS coverage and
accessible frontend acceptance test pass. AI features additionally require an
approved labelled dataset and measured human-override/false-accept thresholds.
