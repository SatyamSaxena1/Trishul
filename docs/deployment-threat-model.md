# Deployment threat model and customer-data gate

**Owners:** customer security owner (approval), deployment administrator (execution)  
**Profiles:** single-host Compose MVP and Kubernetes/OpenShift enterprise deployment  
**Review:** before the first data load and production cutover; after topology, identity, storage, model, runtime, key, or trust-policy changes; and annually.

## Current gate

> **CUSTOMER DATA LOAD IS BLOCKED.** Repository review establishes design intent, not the state of a customer deployment. Every critical/high item in the register is pilot-blocking until deployment evidence satisfies its closure criteria. Do not load repositories, evidence, prompts, reports, identities, or any other customer data until all such rows are `Closed` and the security owner signs this gate.

Synthetic fixtures may be used for validation. Critical/high risks cannot be accepted for the pilot. Lower risks require an owner, rationale, compensating controls, expiry, and security-owner approval. Application readiness is not security-gate evidence.

| Approval field | Required value |
|---|---|
| Site/profile and release image digests | _Unset — pilot-blocking_ |
| Configuration hash, assessment date, assessor | _Unset — pilot-blocking_ |
| Immutable evidence-bundle version ID | _Unset — pilot-blocking_ |
| Critical/high register state | Zero rows not `Closed` |
| Security-owner signature and data-load time | _Unset — no approval_ |

## Scope and objectives

Protected assets are tenant data and metadata; memberships and service scopes; archives, evidence, reports, and presigned URLs; model prompts/responses; PostgreSQL and audit state; secrets and keys; backups/checkpoints; release images/configuration; and service availability.

Threat actors include an Internet attacker, malicious tenant user, compromised account, hostile archive/repository, prompt-injection content, escaped analyzer, stolen workload credential, network attacker, supply-chain compromise, malicious administrator, and an operator able to replace a database or backup. Customer-managed OIDC, S3, model, DNS/CA, registry, backup, ingress, PostgreSQL, and Redis configuration remains in scope.

Objectives are: (1) principals access only their selected tenant and authorized application; (2) analyzers cannot reach the network, host, control plane, secrets, or durable storage except through bounded controller input/output; (3) identity, MFA, TLS, endpoint, and network controls fail closed; (4) each workload receives only required secrets and flows; and (5) privileged audit/backup modification is detectable with independently held keys and checkpoints.

## Components and trust boundaries

| Component | Data and required controls / threats |
|---|---|
| Linux host / cluster nodes | Highest local privilege. Use supported patched OS/kernel, Secure Boot where available, disk encryption, time sync, EDR/audit forwarding, minimal packages, host firewall, no public SSH, and a dedicated rootless runtime. Root/kernel compromise defeats local isolation. |
| Edge proxy | Internet TLS termination. Require TLS 1.2+, approved certificate/ciphers, HSTS/security headers, request/time/body limits, rate limits, trusted forwarding headers, and no metrics/admin exposure. Invalid/plaintext security-sensitive requests fail. |
| API | Authenticates, selects tenant, authorizes, and brokers S3. It has no runtime/model/backup key; uses forced RLS and server-built keys; bounds input and audits security events. |
| Workers/scheduler | Process untrusted task identifiers. Separate ordinary/analysis queues, reload records under tenant context, use least-privilege DB/S3 identities, bound concurrency, and carry no runtime/model/backup key. Redis is not authoritative. |
| Analysis controller | High-value broker. It consumes only the analysis queue and uses a dedicated rootless socket or namespace-only Job/PVC API. It never receives a rootful socket; images are digest-pinned; output is schema/size checked. |
| Rootless runtime/analyzer | Analyzer and input are untrusted. Dedicated non-login UID/user namespace; no network, secrets, token, or runtime socket; read-only root; isolated scratch; no capabilities; no-new-privileges; seccomp; PID/CPU/memory/storage/time limits; cleanup; never run repository code/hooks. |
| PostgreSQL | Authority for tenant/workflow/audit state. Separate owner/migration and runtime roles; forced RLS, same-tenant composite FKs, immutable audit trigger, no runtime BYPASSRLS; verified TLS if external. |
| Redis | Transient authenticated private broker. Use verified TLS if external, no public listener or sensitive payloads, queue/memory limits, and PostgreSQL reconciliation after loss. |
| S3-compatible store | Archives/evidence/reports/results. Deny public access and ACL escalation; use TLS, encryption, versioning/retention, data-access logs, and credential/prefix limits. Canonical keys are `<tenant UUID>/<class>/<opaque server id>` and never client supplied. |
| OIDC | Establishes human identity. Exact issuer/audience/JWKS, approved algorithms/CA, expiry/iat/sub and MFA claims, short sessions, revocation, and no automatic tenant membership. |
| Private model endpoint | Receives minimized prompts. Only AI gateway has its route/credential. Require exact host plus network/IP allowlists, verified HTTPS, no redirect/public fallback, bounded requests, schema-checked untrusted output, and approved retention. |
| Backup storage | Encrypted DB, versioned S3 checkpoint, manifest/config/release, and audit checkpoints. Separate account/admin role and immutable retention; encryption key remains outside application host and backup store except controlled use. |
| Administrator path | Named SSO identities, phishing-resistant MFA, VPN/bastion, PAM/JIT elevation, separate monitored emergency accounts, no shared/root/password login, remote immutable session logs, and dual control for destructive/key actions. |

## Network-flow allowlist

Everything not listed is denied. Record actual source/destination IPs, ports, policy IDs, DNS answers, and denied-flow tests. Compose `internal` networks do not replace a host firewall/egress proxy. Kubernetes requires default deny plus a reviewed site egress policy.

| ID | Source → destination | Allowed data and fail-closed rule |
|---|---|---|
| F1 | Browser → edge, HTTPS 443 | Approved hostname and TLS only; bearer/API/UI traffic. |
| F2 | Edge → API | HTTP only inside isolated local container/pod network, otherwise mTLS; only edge may connect and it overwrites forwarding headers. |
| F3 | API/browser → OIDC, HTTPS 443 | Exact provider origins/JWKS with CA validation; outage never bypasses authentication. |
| F4 | authorized workloads → PostgreSQL, TCP 5432 | Runtime role and `verify-full` TLS when external; owner credential exists only in one-shot migration. |
| F5 | authorized workloads → Redis, TCP/TLS | Private authenticated broker; verified TLS when external. |
| F6 | API/workers/controller → S3, HTTPS 443 | Bucket/prefix-scoped credential and CA verification; analyzer has neither route nor credential. |
| F7 | API/workers → AI gateway | Isolated application network and internal token; edge/users cannot route directly. |
| F8 | AI gateway → private model, HTTPS 443 | Exact hostname and site IP/egress allowlists; private CA as needed; no redirect or fallback. |
| F9 | controller → runtime socket or Kubernetes API | Dedicated Unix rootless socket (never TCP/rootful), or CA-verified API using namespace Job/PVC-only service account. |
| F10 | Kubernetes stager/collector → S3, HTTPS 443 | One-object presigned GET/PUT. Analyzer runs between those phases and has explicit no-network policy. |
| F11 | analyzer → any network | **None**, including DNS and metadata/private networks. |
| F12 | controlled backup operator/job → DB/S3/backup store | Dedicated identities, verified TLS, coordinated checkpoint, immutable destination, out-of-band backup key. |
| F13 | administrator → bastion/PAM → control planes | Private management network, named MFA/JIT identity, source restriction and remote session audit; no direct Internet administration. |
| F14 | workloads → monitoring | Authenticated TLS, metadata-only logs with content/tokens/presigned URLs redacted. |

## Deployment validation

Use two synthetic tenants (`red`, `blue`) and unique canaries. Preserve commands, timestamps, tool versions, sanitized results, configuration, packet/policy logs, and hashes in an immutable evidence bundle. Negative tests must demonstrate denial; inspection alone is insufficient.

### 1. Tenant-isolation enforcement

* Prove the runtime DB role is neither owner, superuser, `BYPASSRLS`, nor owner-role member; only migrations receive owner credentials. Run `python scripts/verify_postgres_security.py` against deployed PostgreSQL and verify forced RLS, policies, grants, immutable audit trigger, and same-tenant FKs.
* For red/blue humans, scoped service accounts, and a multi-membership user, attempt list/get/create/update/delete and forged related IDs across every tenant API resource. Omit/forge `X-Trishul-Tenant`; expect denial or explicit selection, never multi-tenant defaulting.
* Repeat cross-tenant CRUD and relationship writes directly as runtime DB role with absent/red/blue tenant context. Test pooled connection reuse for context leakage. Require no disclosure/change.

### 2. Object-storage key and prefix isolation

* Inventory all DB keys. Require canonical tenant UUID, approved class, opaque server ID; reject leading slash, `..`, encoded separators, user bucket, or mismatched tenant prefix.
* For every workload credential, test list/get/put/delete against allowed, other-tenant, unknown, root, and bypass keys. Anonymous access/ACL changes fail. If an application credential spans tenants, API/RLS negative tests and immutable S3 data-event logs are mandatory compensating controls; per-tenant access points are preferred.
* Verify TLS, encryption, public-access block, versioning/retention, logging, and lifecycle deletion of transient results.

### 3. Analyzer containment

Submit archives attempting traversal, links/devices, bombs/file limits, fork/memory/disk exhaustion, DNS/Internet/metadata/private access, secret/service-account paths, other volumes, and runtime socket. Confirm rejection or bounded termination, no packets/credentials, and cleanup. Inspect the effective workload for digest, non-root, read-only root, dropped capabilities, no-new-privileges, seccomp, resource/deadline bounds, and isolated scratch. For Compose prove the daemon is dedicated/rootless; for Kubernetes prove controller RBAC cannot read Secrets/Pods/logs, exec, or create resources beyond required Jobs/PVCs.

### 4. Secret projection and rotation

Build a principal-to-secret matrix and inspect effective environment, mounts, specs, and permissions. API/worker/scheduler/controller/analyzer must lack model, TLS-private, owner-DB, and backup keys; only AI gateway gets model credentials and only edge gets TLS key. Scan Git, images, config output, arguments, logs, dumps, and backups. Rotate OIDC/client, runtime DB, Redis, S3, Django, internal-AI, metrics, model, TLS, backup, and service-token values; record overlap/restart, successful new value, rejected old value, and audit event.

### 5. OIDC, MFA, and TLS fail-closed behavior

Test missing/malformed/unsigned, wrong algorithm/key/issuer/audience/subject, expired/future, and missing/bad MFA `amr`/`acr` tokens. Test JWKS outage/rotation: access denies rather than trusting stale/unverified claims. Confirm no automatic membership. Test plaintext/obsolete TLS, bad hostname, expired/untrusted/revoked certificates, bad private CA, proxy-header spoofing, and every external dependency. External PostgreSQL/Redis and all OIDC/S3/model/Kubernetes/backup/admin flows reject invalid peers.

### 6. Presigned URL scope and expiry

Using synthetic objects, inspect without logging the URL: input is GET-only, output PUT-only, exact bucket/key, no list/delete/ACL, signed headers, opaque name, HTTPS, and phase-minimal expiry (900 seconds maximum). Try method/key/header substitution, premature use, and post-expiry use. Restrict Job-spec readers because URLs appear in commands; prove query strings are redacted from logs. Delete transient output and rotate credentials after suspected exposure.

### 7. AI endpoint allowlisting

Prove only AI gateway has model DNS/IP egress and credential. Empty/unlisted host, HTTP/user-info URL, redirect, DNS rebinding/change, loopback/link-local/metadata/reserved/multicast, untrusted certificate, and public endpoint must fail with no fallback. Match application hostname allowlist to firewall/NetworkPolicy/proxy destinations. Verify prompt minimization/redaction, size/budget bounds, response-schema checks, retention approval, and no prompt/response logs.

### 8. Backup-key separation

Prove the encryption key uses a separate vault/account and admin role from application secrets and backup objects and is not continuously on the host or in workloads, source, S3, or evidence. Verify AES-256-GCM rejects changed/truncated data. Make coordinated DB/S3 and audit checkpoints, store an immutable encrypted recovery set, and restore to an isolated clean deployment using independently retrieved keys. Test lost-key/revoked-operator procedures.

### 9. Audit-chain verification and checkpoint storage

Generate tenant events, run `python manage.py verify_audit`, and compare each terminal hash with an independently stored manifest/checkpoint. At least daily and around upgrades/backups, sign/timestamp checkpoints into immutable storage administered separately from PostgreSQL/application. Prove runtime cannot update/delete events. In an isolated copy, mutate/delete/reorder an event and replace an entire internally consistent chain/database: local verification detects event changes and external comparison detects whole-chain replacement. Alert and block restore/cutover on failure.

### 10. Host hardening and administrative access

Record OS/kernel/runtime versions, patch SLA, CIS/vendor scan, disk encryption/Secure Boot, firewall/listeners, time sync, audit/EDR forwarding, filesystem modes, daemon config, and vulnerability scan. Confirm UID mappings/socket ownership, no privileged/host PID/network containers or sensitive mounts, and signed digest-pinned images. Test named SSO plus phishing-resistant MFA, bastion/VPN, JIT/PAM, disabled direct root/password/shared login, emergency monitoring, remote immutable command/session audit, dual control, and prompt revocation.

## Critical/high finding register

This is authoritative for the pilot. Never delete rows; close them with immutable evidence or add a superseding row. `Pilot-blocking` is unresolved, not accepted.

| ID | Severity | Finding | Closure evidence | Owner | Status |
|---|---|---|---|---|---|
| DTM-001 | Critical | Deployment tenant/RLS behavior and runtime grants are unproven. | Validation 1: passing script, role/grant output, API/SQL red-blue matrix, pooled-context test. | App + DBA | **Pilot-blocking** |
| DTM-002 | High | Site S3 IAM, canonical keys, public block, and prefix isolation are unknown. | Validation 2: policy/key inventory, red-blue negative results, encryption/version/log proof. | Storage | **Pilot-blocking** |
| DTM-003 | Critical | Analyzer/rootless containment is unproven on selected kernel/runtime/cluster. | Validation 3: daemon/RBAC/spec, hostile corpus, packet/policy, resource and cleanup results. | Platform | **Pilot-blocking** |
| DTM-004 | High | Deployment secret least privilege and rotation/revocation are unproven. | Validation 4: approved matrix, workload/repository/image/log scans, rotation records rejecting old values. | Secrets | **Pilot-blocking** |
| DTM-005 | Critical | Site OIDC/MFA, proxy trust, certificates, and dependency TLS failure are untested. | Validation 5: IdP configuration and negative token/TLS matrix. | IAM + network | **Pilot-blocking** |
| DTM-006 | High | Selected S3 presigned URL semantics and Job-spec exposure are untested. | Validation 6: sanitized method/key/expiry/bypass results, RBAC and redaction proof. | App + storage | **Pilot-blocking** |
| DTM-007 | High | AI application/network allowlists may diverge or allow rebound/public endpoints. | Validation 7: exact allowlists, negative tests, DNS procedure, policy logs, retention approval. | AI + network | **Pilot-blocking** |
| DTM-008 | Critical | Backup-key separation, immutable recovery custody, and restore are unproven. | Validation 8: IAM separation, tamper result, immutable version IDs, clean restore. Never attach key. | Backup + security | **Pilot-blocking** |
| DTM-009 | High | A DBA can replace a consistent audit chain absent independent checkpoints. | Validation 9: signed checkpoint IDs, schedule/alert, mutation and whole-chain replacement tests. | Audit + security | **Pilot-blocking** |
| DTM-010 | Critical | Host/node hardening and privileged administration are unevidenced. | Validation 10: remediated critical/high scan, firewall/runtime/access/session tests, approval. | Platform + IAM | **Pilot-blocking** |

On discovery of another critical/high issue, stop onboarding/processing, preserve evidence, add an owned row immediately, and mark it `Pilot-blocking`. If data is present, invoke incident response. Reopen closed rows when evidence expires or a review trigger changes the control.

## Closure workflow and residual risk

1. Control owner runs validation with synthetic data and records immutable evidence version IDs.
2. An independent assessor reproduces each critical/high negative test, recording date, digest, configuration hash, and tool versions.
3. Security owner changes a row only to `Closed (date, evidence ID)` after every criterion passes; partial remediation remains blocked.
4. Re-run the whole gate and mechanically confirm zero critical/high rows not closed. Security owner signs; only then may the administrator record a customer-data-load time and open onboarding.
5. Store this model, signed gate, sanitized output, external checkpoints, release manifest, and configuration hash in separately administered immutable storage. Never include secrets, tokens, presigned URLs, customer data, or exploitable private topology.

Closure is point-in-time evidence, not elimination of zero-day kernel/runtime compromise, fully privileged malicious administrators, dependency compromise, traffic analysis, denial of service, or loss of a single Compose host. Address these through patching, separation of duties, signed provenance, monitoring/response, capacity limits, immutable backups, and multi-failure-domain enterprise deployment where availability requires it.
