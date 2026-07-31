# Design-partner pilot onboarding checklist

Complete this checklist for the design partner and **two to five named human reviewers** before any customer repository is uploaded. The pilot owner retains the completed checklist and the non-sensitive access-test record with the pilot's security records. A checkbox is complete only when the responsible person records their name, date, and the requested evidence reference.

## Pilot record and responsibilities

- [ ] Record the design-partner organization, intended tenant UUID and tenant name, pilot start and planned end dates, data classification, and pilot owner.
- [ ] Name **2–5 reviewers** in the roster below. Identify one tenant administrator who provisions access, one security contact who owns incidents, and one pilot owner who approves repository uploads. One person may fill more than one of these roles, but reviewers must use individual identities rather than shared accounts.
- [ ] Record the approved repository names and owners. Approval is repository-specific; it does not authorize uploading every repository owned by the partner.

| Participant | Organization | Pilot responsibility | Intended role | Repository scope | Start date | End date | Approval/evidence reference |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Design-partner owner |  | Pilot owner / upload approver |  |  |  |  |  |
| Reviewer 1 |  |  |  |  |  |  |  |
| Reviewer 2 |  |  |  |  |  |  |  |
| Reviewer 3 (optional) |  |  |  |  |  |  |  |
| Reviewer 4 (optional) |  |  |  |  |  |  |  |
| Reviewer 5 (optional) |  |  |  |  |  |  |  |

## Identity, membership, and least privilege

Complete these items separately for every rostered participant.

- [ ] **OIDC identity and MFA:** the participant signs in through the approved corporate OIDC provider using their individual account. Verify the expected issuer, subject/email, and successful MFA claim; do not accept a password-only session or a screenshot of a password. Record only the participant, timestamp, issuer, and pass/fail result—never an access token, MFA code, or full token claims.
- [ ] **Explicit tenant membership:** the tenant administrator adds an active membership for the participant to the intended tenant. Confirm that login alone created no membership and that the UI/API context shows the intended tenant UUID and name.
- [ ] **Least-privilege role:** select the narrowest built-in role needed for pilot duties and document the reason. Prefer `developer` for remediation, `appsec` for repository import/scanning/triage, `architect` for threat review, `assessor` for assessment work, and read-oriented `manager`, `auditor`, or `executive` roles where appropriate. Do not grant `admin` merely for convenience. Time-box all access to the pilot end date.
- [ ] Have the participant demonstrate only their approved workflow. Remove excess roles, memberships, application scope, or service-token scopes discovered during the demonstration.

## Mandatory pre-upload authorization gate

The pilot owner and tenant administrator must complete and sign this gate **before the first customer repository upload** and repeat it after material identity, tenancy, authorization, or deployment changes.

- [ ] Obtain written authorization from the repository owner that identifies the exact repository and branch/tag or snapshot, intended tenant, permitted upload operator, allowed analysis purpose, data classification, and approval expiry.
- [ ] Confirm the upload operator has an active membership in the intended tenant and the `appsec` role (or a separately approved principal limited to `repository.import`). If automation is necessary, use a short-lived, revocable service token scoped to `repository.import` and only the approved application; do not use an administrator token.
- [ ] Screen the upload for unsupported or prohibited material and remove secrets, credentials, personal data, production exports, unnecessary history, and files outside the approved scope. Never upload a live working directory without reviewing its contents.
- [ ] Confirm retention, deletion, evidence, model-routing, and backup expectations with the repository owner.
- [ ] **Perform and retain the cross-tenant negative-access check below.** No customer source may be uploaded until the result is a clean pass.
- [ ] Pilot owner records the authorization decision, approver, UTC timestamp, repository/snapshot identifier, intended tenant UUID, operator, role/scope, negative-test evidence reference, and approval expiry.

### Cross-tenant negative-access check

Use synthetic, non-customer fixtures in two test tenants: tenant A (the operator's intended tenant) and tenant B (the control tenant). Use the same production-equivalent OIDC and authorization path as the planned upload.

1. Create a harmless, uniquely named fixture in each tenant and record their non-sensitive IDs. Give the upload operator membership only in tenant A.
2. With the operator's MFA-authenticated session and `X-Trishul-Tenant` set to tenant A, verify that list and detail requests can see tenant A's fixture but cannot see tenant B's fixture.
3. Set `X-Trishul-Tenant` to tenant B's UUID and verify the request is denied because the operator has no membership. Also try tenant B's fixture ID through the relevant detail endpoint while tenant A is selected and verify a fail-closed response with no control-tenant fields or object contents.
4. Attempt a repository create/import against tenant B's application ID while tenant A is selected. Verify denial and verify independently that no repository, repository version, upload object, or scan was created in either tenant.
5. If a service token will perform uploads, repeat steps 2–4 with that exact token class and application restriction. Revoke the test token after the check.
6. Treat any cross-tenant data, metadata, differing response that exposes object existence, or partial write as a failure. Stop onboarding, upload no customer source, preserve relevant non-secret logs, and use the incident path below. Retest only after remediation.

Retain a sanitized test record containing the date/time, environment/release, tester and witness, participant/principal identifier, tenant A and B non-sensitive IDs, tested endpoint and method, expected versus actual status/result, confirmation of no writes, result, and audit/log event references. Redact authorization headers, cookies, tokens, OIDC claims, source/snippets, signed URLs, credentials, and customer data. A concise command transcript with those values replaced by labels is acceptable. The tester and pilot owner must sign the pass record.

| Check | Expected result | Actual result / evidence reference | Tester and UTC date | Witness / pilot-owner sign-off |
| --- | --- | --- | --- | --- |
| A list/detail permits A and omits B | Only tenant A fixture is returned |  |  |  |
| Tenant selector set to B | Denied: no membership |  |  |  |
| B object requested in A context | Fail closed; no B data disclosed |  |  |  |
| Create/import against B application | Denied; no object, version, upload, or scan created |  |  |  |
| Upload service token (if used) | Same isolation; token then revoked |  |  |  |

## Reviewer orientation

- [ ] Show reviewers where outcomes appear: **Code findings** in the application dashboard and the finding detail/API record. Explain that severity and confidence aid prioritization; neither is proof by itself.
- [ ] Review and acknowledge the finding definitions:
  - `candidate`: analyzer output awaiting human review.
  - `needs_validation`: evidence is insufficient or additional reproduction/context is required.
  - `confirmed`: a human reviewer validated the issue against relevant evidence and context.
  - `false_positive`: the reported pattern does not represent the claimed issue in this context; record the rationale.
  - `remediation_pending`: the issue is validated and a fix or compensating action is in progress.
  - `resolved`: remediation was verified against a new revision or other documented evidence.
- [ ] Require reviewers to record rationale for every transition and distinguish a finding outcome from risk acceptance, threat status, assessment conclusion, and remediation verification. Model output cannot confirm a finding or approve an assessment.

## Evidence and safe collaboration

- [ ] Handle repository source, snippets, findings, reports, assessment artifacts, and model inputs/outputs at the same classification as the customer repository unless the data owner assigns a stricter classification.
- [ ] Collect the minimum evidence needed; prefer file path, line range, version identifier, and integrity hash over copied source. Keep provenance, collection date, repository revision, and reviewer attribution. Do not alter evidence; add a new version or annotation instead.
- [ ] Store evidence only in the approved tenant and approved customer-controlled storage. Do not download it to unmanaged devices or move it to personal drives, email, chat, tickets, or another tenant. Share/export only with explicitly authorized recipients and follow the agreed retention/deletion schedule.
- [ ] Treat repository content, comments, evidence, retrieved text, and model responses as untrusted data—not instructions or authorization. Escalate suspected prompt injection or malicious content.
- [ ] **Never place secrets in comments, finding notes, assessment responses, support tickets, or model prompts.** This includes passwords, API keys, access/refresh/service tokens, cookies, private keys, MFA codes, signed URLs, connection strings, and secret-bearing configuration. Stop, revoke/rotate the secret, and follow the incident process if exposure occurs.

## Incident, support, and revocation readiness

- [ ] Record and test the contacts before access is enabled. Do not put secret material in the contact record or initial report.

| Purpose | Primary contact / monitored channel | Backup / escalation | Coverage and response target |
| --- | --- | --- | --- |
| Security incident (cross-tenant access, secret/source exposure, suspicious login) |  |  |  |
| Product/technical support |  |  |  |
| Customer repository/data owner |  |  |  |
| Customer identity/OIDC administrator |  |  |  |
| Tenant/application administrator |  |  |  |

- [ ] Rehearse the immediate incident actions: stop uploads/analysis, preserve non-sensitive audit references, notify the security contact, revoke affected sessions/tokens, rotate exposed credentials, and do not delete relevant evidence unless directed by incident response.
- [ ] Demonstrate session and token revocation. The identity administrator can terminate OIDC sessions and revoke refresh/access grants; the tenant administrator can deactivate membership; the application administrator can revoke service tokens. Verify a revoked session/token can no longer access the API, and record the sanitized audit reference.
- [ ] Define triggers for immediate revocation: lost device, role/organization change, suspected compromise, accidental disclosure, cross-tenant failure, prolonged inactivity, or participant departure.

## Pilot closeout and access removal

Complete on the earliest of the participant's end date, departure, or pilot termination.

- [ ] Disable every pilot membership and remove temporary elevated roles and application restrictions/grants. Remove pilot OIDC group assignments where used.
- [ ] Revoke every pilot service token, API token, active session, refresh grant, signed upload URL, and temporary credential; rotate any shared integration credential that could not be individually revoked.
- [ ] Verify former participants and automation receive denial, and review the membership/service-account inventory for orphaned access.
- [ ] Reconcile approved repositories, evidence, reports, exports, backups, and local copies against the agreed return/deletion/retention plan. Obtain data-owner confirmation without copying sensitive content into the closeout record.
- [ ] Record completion date, responsible administrator, verification result, exceptions with owners/deadlines, and non-sensitive audit references. Pilot owner signs final closure.

## Final authorization

- [ ] The design-partner owner confirms the roster, repository scope, evidence rules, contacts, and end date.
- [ ] All 2–5 reviewers acknowledge finding definitions, safe evidence handling, and the prohibition on secrets in comments or model prompts.
- [ ] The tenant administrator confirms explicit memberships, least privilege, and revocation readiness.
- [ ] The pilot owner confirms the cross-tenant negative-access check passed and its sanitized evidence is retained, then authorizes the first customer-repository upload.
