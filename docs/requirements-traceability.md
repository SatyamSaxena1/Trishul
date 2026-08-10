# Concept-note requirements traceability

Baseline: `main` at `6324a59` on 10 August 2026, plus the active evidence-versioning slice.

Status is deliberately conservative: **implemented** means a usable, tested path;
**partial** means a schema, API, or narrow path exists; **planned** means no
material end-to-end implementation exists. This matrix is the release gate for
the GRC/TPRM programme, not a compliance attestation.

## Module delivery gate

| Requirement group | Status | Evidence | Required completion slice |
| --- | --- | --- | --- |
| M1 tenancy, identity and onboarding | Partial | Tenant/RLS/membership/engagement models and OIDC | SAML, SCIM, tenant IdP configuration, session controls, full persona journeys |
| M2 UCF and mappings | Partial | Versioned framework, requirement, UCO, mapping and delta models | Expert-approved ISO and DPDP packs, pack review/diff and instantiation |
| M3 scope and assets | Partial | Organisation, workspace and application records | Entities, locations, assets, ownership and applicability wizard |
| M4 evidence | Partial | Immutable evidence records, hashes, append-only supersession API and object storage | Safe object upload, extraction, classification, attributes, quality and version propagation |
| M5 evidence intelligence and reuse | Planned | AI gateway/run records only | Retrieval, freshness/scope/sufficiency, cited proposal and human approval |
| M6 scoring | Partial | Risk scores and limited status counts | Configurable scores, caps, snapshots, drill-down and trends |
| M7 policy lifecycle | Planned | Deployment policy packs are not GRC policies | Authoring, approval, publication, attestation and expiry |
| M8 risk | Partial | Risk, remediation, task, acceptance and approval models | Appetite, treatment workflow, heat maps, KRI and role journeys |
| M9 TPRM | Planned | Vendor role/entitlement vocabulary only | Vendor, tiering, questionnaires, portal, campaigns, scoring and monitoring |
| M10 auditor workbench | Partial | Scoped engagements, verdicts, locks and workflow history | Review screen, sampling, CAPA, QA and sealed report |
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
| BR-55 | Evidence is never overwritten. | Partial | Append-only version API and model/database constraint tests exist; add safe object upload and PostgreSQL trigger integration evidence. |
| BR-56 | Superseded evidence is independently revalidated on every link. | Planned | Reuse propagation and gap/task idempotency tests. |
| BR-57 | Locked controls are excluded from automatic propagation. | Partial | Auditor verdict lock exists; propagation/notification test required. |
| BR-58 | Auditor-closed controls become auditee read-only. | Partial | Enforce every evidence/control write path, not only verdict API. |
| BR-59 | Unlock requires authority, reason and audit record. | Implemented | Reasoned manager-unlock and immutable-history tests. |
| BR-60 | Failed validation gives an actionable re-upload request. | Planned | Freshness, scope and sufficiency failure scenarios. |
| BR-61 | AI never issues final audit verdicts. | Partial | Suggestion-only AI contract and human-verdict integration tests. |
| BR-62 | AI decisions preserve provider/model/prompt/sources/confidence. | Partial | Immutable AI-run schema with citation and prompt tests. |
| BR-63 | Critical non-compliance caps framework score. | Planned | Configurable score/cap test suite. |
| BR-64 | Not Applicable requires justification and is excluded from scoring. | Partial | Validation and score-exclusion tests. |
| BR-65 | Below-threshold evidence requires a justified override. | Planned | Quality threshold and override audit test. |
| BR-66 | Evidence uploader cannot verdict the same control. | Partial | Cross-identity verdict denial test. |
| BR-67 | Overdue policies reduce supported-control maturity. | Planned | Policy expiry scheduler and maturity recalculation test. |
| BR-68 | Unevidenced vendor claims receive reduced score credit. | Planned | Vendor scoring test. |
| BR-69 | Vendor disqualifiers override aggregate score. | Planned | Configurable disqualifier test. |
| BR-70 | Failed evidence collection alerts operators. | Planned | Connector failure, retry and alert test. |
| BR-71 | Tenant scoping is enforced for every query. | Partial | Static CI check plus PostgreSQL forced-RLS integration suite. |
| BR-72 | Every score drills down to an artefact. | Planned | Snapshot-to-control-to-evidence drill-down test. |

## Completion rule

No module is marked implemented until its required role journey, negative
authorization cases, immutable audit history, PostgreSQL RLS coverage and
accessible frontend acceptance test pass. AI features additionally require an
approved labelled dataset and measured human-override/false-accept thresholds.
