# Pilot acceptance specification

**Specification version:** 1.0.0  
**Status:** Baseline for pilot release acceptance  
**Effective date:** 2026-08-03  
**Applies to:** the customer-hosted Docker Compose pilot profile

Changes to a check, its expected result, or its pass criterion require a new
semantic version of this document. Editorial clarifications increment the patch
version; added or materially changed checks increment the minor version; removal
or relaxation of a security or recovery requirement increments the major version.
The release record must contain the specification version and Git commit tested.

## Acceptance record and rules

The release manager creates one immutable evidence directory named
`acceptance/<release>/<run-UTC>/`. It contains `environment.md` (image digests,
Git commit, VM shape, OS, Compose version, configuration with secrets redacted,
tester names, and start/end times), `results.csv` (check ID, result, owner,
timestamp, and evidence links), command output, exported audit events, API
responses, database/object-store observations, and screenshots where called for.
Logs must be exported from the central log sink and must not contain source,
evidence snippets, tokens, credentials, or presigned URL query strings.

Unless a check says otherwise, use two disposable tenants, **Alpha** and **Beta**,
with separate users, service accounts, applications, repositories, and bucket
prefixes. Use synthetic source containing markers unique to each tenant. Record a
pre-run database row count and object inventory. Run automated mappings against
the exact candidate commit with:

```sh
python -m pytest <node-id>
```

An automated mapping is supporting evidence, not a substitute for a mapped drill.
Every listed mapping must pass. A drill passes only when its expected outcome is
observed, no other tenant is affected, retained evidence is complete and
redacted, and cleanup succeeds. Any unexpected data disclosure, cross-tenant
access, unbounded retry, or fail-open behavior is an automatic release failure.
The named **pass/fail owner** makes the decision; the Release Manager records it
and may not overrule a Security or Operations failure. Failed checks require an
issue link and a complete rerun after remediation—partial waivers do not satisfy
this specification.

## Functional and hostile-input checks

| ID | Check and mapping | Prerequisites and procedure | Expected outcome | Retained evidence | Cleanup | Pass/fail owner |
|---|---|---|---|---|---|---|
| ARC-01 | Valid ZIP completion. Drill **D-ARC-VALID**; supporting tests `backend/core/tests/test_archive.py::test_archive_inventory_does_not_extract_source` and `backend/core/tests/test_analyzer.py::test_python_pack_finds_only_evidence_backed_calls`. | Alpha user and a ZIP below every configured limit, containing a synthetic `PY001` and `PY002` case. Submit through the public API, wait to a terminal state, then retrieve the scan and findings. | One scan completes; archive digest/inventory and coverage are recorded; each finding has rule/version, file path, line range, and snippet hash that resolves to the submitted file; source text is absent from logs. | Redacted request/response, archive SHA-256, scan/finding export, audit events, worker/analyzer logs, and an operator verification of each evidence link. | Delete scan, repository/version, input and result objects; verify prefix empty. | Product QA Lead |
| ARC-02 | Valid TAR completion. Drill **D-ARC-VALID** with the same supporting analyzer test as ARC-01. | Repeat ARC-01 with a standards-compliant TAR containing the same synthetic cases. | Same as ARC-01, with TAR identified and no extraction outside the analyzer workspace. | Same artifacts as ARC-01 plus TAR member listing and SHA-256. | Same as ARC-01. | Product QA Lead |
| ARC-03 | Empty archive. Drill **D-ARC-NEGATIVE**. | Submit valid empty ZIP and empty TAR fixtures. | Both requests are rejected with a stable 4xx validation code; no scan or analyzer job is created, and neither input is retained beyond the rejected-upload retention policy. | Fixture hashes, responses/state history, audit event, logs, and queue-depth sample. | Delete fixtures/objects and any scan records. | Product QA Lead |
| ARC-04 | Unsupported format. Drill **D-ARC-NEGATIVE**. | Submit plain text and a gzip that is not a TAR, each with an archive-looking filename. | Both are rejected as unsupported/invalid; no analyzer job is launched and no source is persisted beyond the rejected-upload retention policy. | Fixture hashes, redacted responses, audit/log evidence, job count before/after, object inventory. | Remove upload remnants. | Product QA Lead |
| ARC-05 | Oversized input. Drill **D-ARC-NEGATIVE**. | Submit one fixture just over the compressed limit and archives with a member over the per-file limit, too many members, excessive depth, and total declared expansion over the extracted limit. | Each is rejected before analysis with a bounded validation response; no partial extraction, analyzer launch, or durable orphan object occurs. | Limits/config snapshot, fixture generator and hashes, response, resource graph, job/object before/after. | Remove generated fixtures and upload remnants. | Security Lead |
| ARC-06 | Traversal. Automated mapping `backend/core/tests/test_archive.py::test_archive_rejects_paths_outside_root`; drill **D-ARC-NEGATIVE**. | Submit ZIP and TAR variants containing `../`, absolute, drive-qualified, backslash, and NUL/depth boundary names. | Every variant is rejected; no file appears outside the scratch root and no analyzer starts. | Pytest output, fixture member lists/hashes, response/logs, and before/after scratch filesystem inventory. | Destroy scratch volume and fixtures. | Security Lead |
| ARC-07 | Symlink/special entry. Drill **D-ARC-NEGATIVE**. | Submit ZIP symlink and TAR symlink, hard-link, device, and FIFO entries, including links targeting outside the root. | Every archive is rejected before analysis; no link target is read or created. | Fixture creation script/hashes, member metadata, responses, analyzer job count, scratch inventory. | Destroy scratch volume and fixtures. | Security Lead |
| ARC-08 | Archive bomb. Drill **D-ARC-NEGATIVE**. | In an isolated test VM, submit a highly compressible archive whose declared expansion exceeds the total limit and a many-member bomb; enable CPU, memory, disk, and elapsed-time sampling. | Rejected from metadata without expansion; configured resource limits remain intact, service stays ready, and no disk-pressure condition or orphan job remains. | Fixture recipe/hash, metrics graph, response, readiness samples, job/object inventory, logs. Never retain the expanded payload. | Delete fixture and scratch data; confirm disk space and readiness recover. | Security Lead |
| ARC-09 | Malformed/truncated ZIP and TAR. Drill **D-ARC-NEGATIVE**. | Submit truncated headers/directories, corrupt checksums, and random-byte fixtures. | Stable invalid-archive failure; no uncaught API error, worker retry storm, analyzer launch, or orphan object. | Fixture hashes, responses, state/audit history, logs, queue and object before/after. | Remove fixtures and remnants. | Product QA Lead |

**D-ARC-VALID:** create the fixture reproducibly, record its manifest and digest,
submit it only through the supported upload/API path, poll rather than modifying
state directly, verify every evidence locator against the fixture, and perform the
listed cleanup. **D-ARC-NEGATIVE:** generate each hostile fixture without
extracting it on the application host, submit one at a time, observe API, queue,
analyzer, scratch, and object-store state through the terminal result, and verify
that readiness remains healthy.

## Resilience, idempotency, and capacity checks

| ID | Check and mapping | Prerequisites and procedure | Expected outcome | Retained evidence | Cleanup | Pass/fail owner |
|---|---|---|---|---|---|---|
| RES-01 | Worker crash. Drill **D-RES-FAULT**. | Start an Alpha scan, identify the executing worker, send `SIGKILL` after RUNNING, and restart it after the lease/retry interval. | The task is redelivered or reconciled within the documented recovery objective; exactly one terminal scan and one logical set of findings exist; attempts are bounded and an audit/alert signal exists. | Timed state/queue trace, kill/restart commands, worker logs, alerts, finding/fingerprint counts, audit export. | Remove scan and objects; restore worker count. | Operations Lead |
| RES-02 | Analyzer timeout. Drill **D-RES-FAULT**. | Use an approved test analyzer that sleeps beyond the configured timeout. | Controller terminates it, marks a stable failed state/error, releases scratch resources, emits telemetry, and remains ready; retries do not exceed policy. | Timeout/resource configuration, pod/container timeline, process listing, state/audit/log/alert evidence. | Restore production analyzer digest; delete job/volume/result artifacts. | Operations Lead |
| RES-03 | Storage outage. Drill **D-RES-FAULT**. | Block application/worker access to the test S3 endpoint during upload and separately during result collection; restore it after the observation window. | Readiness becomes unhealthy, operations fail closed without data loss/cross-tenant fallback, errors are bounded and actionable, and queued work completes or reaches an explicit retryable/failed state after restoration. | Firewall/proxy change, readiness timeline, API/state responses, retry/queue metrics, logs/alerts, object checksum after recovery. | Restore route; remove test objects and verify readiness. | Operations Lead |
| RES-04 | Queue disruption. Drill **D-RES-FAULT**. | Stop Redis while one task is queued and one is running, attempt another submission, then restart Redis. | Readiness fails; submissions do not falsely report execution; no task is lost or duplicated; recovery is automatic or uses the documented reconciliation action with bounded attempts. | Compose commands, readiness/API/task timelines, Redis/worker logs, queue metrics, terminal scan and finding counts. | Restart queue/workers, drain test tasks, delete test scans. | Operations Lead |
| RES-05 | Host restart. Drill **D-RES-FAULT**. | During a RUNNING scan reboot the pilot VM (not merely containers), then execute the normal startup/readiness procedure. | Durable state and objects survive; services become ready within the pilot recovery objective; interrupted work is safely completed or explicitly failed/requeued; audit chain verifies and no duplicate findings appear. | VM/boot timestamps, service/readiness timeline, pre/post DB and object checksums, scan/finding counts, `verify_audit` output, alerts. | Remove test data and confirm all expected services healthy. | Operations Lead |
| IDE-01 | Duplicate submission. Drill **D-IDEMPOTENCY**. | Send two simultaneous identical submissions using the same supported idempotency key; repeat after the first response is lost at the client. | The published API contract is enforced: a single logical repository version/scan is returned or an explicit duplicate conflict is returned; never two charged analyses or finding sets. | Timestamped HTTP transcripts, idempotency key hash (not token), DB/job/object counts, audit and analyzer-launch count. | Delete the logical scan and objects. | Product QA Lead |
| IDE-02 | Task redelivery. Drill **D-IDEMPOTENCY**; supporting behavior is the late-ack task and terminal-state guard exercised operationally. | Force broker redelivery of the same task after analysis starts and again after completion. | At most one transition creates findings; terminal redelivery is a no-op; fingerprint, evidence, job, and audit rows are not duplicated and tenant context is preserved. | Delivery IDs/timestamps, worker logs, before/after row queries, finding fingerprints, audit export, object inventory. | Purge test message and delete scan/objects. | Engineering Lead |
| CAP-01 | Five concurrent pilot-sized scans under VM limits. Drill **D-CAPACITY**. | Dedicated VM with the supported minimum of 4 vCPU, 12 GiB RAM, 50 GiB local disk plus object capacity; default production limits; five representative, non-secret pilot archives whose sizes/member counts and expected findings are recorded. Submit within 10 seconds. | All five reach COMPLETED without manual intervention, lost/duplicate findings, OOM kill, disk pressure, or readiness failure. CPU/memory/PID/disk ceilings remain enforced. Record elapsed time and peak utilization as the pilot baseline; any configured pilot SLO must also pass. | VM/config snapshot, fixture hashes/manifests, submission/state timeline, per-scan outputs, queue depth, cgroup/container CPU-memory-PID, disk and readiness graphs, logs/alerts. | Delete five scans and all objects/scratch volumes; verify baseline disk, empty queue, readiness. | Performance Lead |

**D-RES-FAULT:** announce the fault window, capture a healthy baseline, inject only
the named fault, time every transition using UTC, restore the dependency, wait for
a terminal state, verify integrity and readiness, then clean up. **D-IDEMPOTENCY:**
use a request/message correlation ID, retain row counts and immutable identifiers
before and after each delivery, and compare logical findings by fingerprint.
**D-CAPACITY:** prohibit other workloads on the VM, sample resource and readiness
metrics at no more than 10-second intervals from one minute before submission
through two minutes after the final terminal state, and retain raw metric exports.

## Tenant and boundary security checks

| ID | Check and mapping | Prerequisites and procedure | Expected outcome | Retained evidence | Cleanup | Pass/fail owner |
|---|---|---|---|---|---|---|
| TEN-01 | Cross-tenant API denial. Automated mappings `backend/core/tests/test_security.py::test_service_token_and_tenant_manager_fail_closed` and `::test_application_restrictions_apply_to_lists_and_writes`; drill **D-TENANT**. | Authenticate as Alpha and attempt list, retrieve, update, delete, scan/finding/evidence download, and guessed-ID access to Beta resources. | Responses are 403/404 without existence-sensitive differences; lists contain only Alpha; no Beta mutation, audit leakage, or presigned URL is produced. | Pytest output, redacted HTTP matrix, Alpha/Beta row/object hashes, audit events and authorization alert. | Revoke test tokens; remove test resources. | Security Lead |
| TEN-02 | Cross-tenant database denial. Automated mapping `backend/core/tests/test_security.py::test_cross_tenant_relationship_is_rejected`; drill **D-TENANT**. | Using the runtime DB role, set Alpha tenant context and attempt SELECT/INSERT/UPDATE/DELETE and cross-tenant FK creation against Beta IDs on every tenant-owned table. Also try with tenant context unset. | PostgreSQL RLS/FKs deny or return zero rows; no direct or relational change occurs; unset context fails closed. | Pytest output, role grants/RLS policy export, SQL transcript with IDs redacted, before/after table checksums/counts, DB audit logs. | Roll back transaction; remove test principals/data. | Security Lead |
| TEN-03 | Cross-tenant object-storage denial. Drill **D-TENANT**. | With Alpha application credentials and Alpha presigned URLs, attempt list/get/put/delete/copy against Beta keys; alter key/path/query and retry after URL expiry. | All Beta operations are denied; bucket listing does not reveal Beta; signatures cannot be retargeted; Beta object checksum is unchanged. | Redacted S3 request/status matrix, bucket/IAM policy snapshot, object checksums and access logs (query signatures removed). | Revoke URLs/credentials and remove Alpha test objects. | Security Lead |
| ISO-01 | Analyzer credential isolation. Automated mapping `backend/core/tests/test_kubernetes_runner.py::test_analyzer_job_has_no_token_network_credentials_or_privilege`; drill **D-ANALYZER-ISO** on Compose. | Run an instrumented, approved analyzer that records environment variable names, mounts, UID/capabilities, and service-account metadata availability without recording values. | No application, DB, S3, OIDC, AI/model, runtime-socket, presigned URL, or service-account credential is present; filesystem/capabilities match the hardened contract. | Pytest output, image digest, redacted env-name/mount/capability report, container/job spec and controller logs. | Delete instrumented job/image from host and restore approved digest. | Security Lead |
| ISO-02 | Analyzer network isolation. Drill **D-ANALYZER-ISO**. | Instrumented analyzer attempts DNS and TCP/HTTP to public internet, application, DB, queue, object store, model endpoint, metadata service, and a controlled canary listener. | Every attempt fails; canary records no connection; scan result can only be written through its designated output volume. | Network policy/runtime config, destinations and results, canary logs, packet/firewall counters, job spec and image digest. | Remove canary/instrumented job and restore configuration. | Security Lead |

**D-TENANT:** create matched Alpha/Beta resources, record Beta canary row/object
hashes, run each operation only with least-privileged Alpha credentials, and
compare canaries afterward. Do not use an administrator credential for the denial
attempt. **D-ANALYZER-ISO:** approve and hash the instrumented image before the
test, make probes non-destructive and bounded, run it through the real controller,
and have Security review both attempted destinations and absent credential names.

## Fail-closed identity, transport, and configuration checks

| ID | Check and mapping | Prerequisites and procedure | Expected outcome | Retained evidence | Cleanup | Pass/fail owner |
|---|---|---|---|---|---|---|
| SEC-01 | OIDC validation. Drill **D-FAIL-CLOSED**. | Against the pilot IdP, try missing/invalid signature, wrong issuer/audience, expired/not-yet-valid token, missing subject, unknown membership, and key rotation/IdP outage. | Every invalid token is denied without membership creation; outage does not fall back to local/anonymous auth; a valid control token succeeds. | Redacted response matrix, OIDC config/JWKS thumbprints, auth logs/alerts, membership before/after. | Revoke sessions/test user and restore IdP state. | Identity Lead |
| SEC-02 | MFA claim. Drill **D-FAIL-CLOSED**. | Use otherwise-valid tokens with absent, false, malformed, and required MFA claim, plus a valid MFA control. | All nonconforming claims are denied; only the configured MFA claim/value succeeds; service-token behavior remains explicitly scoped and unchanged. | Redacted decoded claim shapes (no token), HTTP results, config, auth logs. | Revoke tokens/test sessions. | Identity Lead |
| SEC-03 | TLS. Drill **D-FAIL-CLOSED**. | Test HTTP, TLS below the supported minimum, expired/self-signed/wrong-host/untrusted certificates, and valid TLS at edge and outbound model/object endpoints. | HTTP redirects or is refused per deployment contract without accepting credentials; invalid TLS is rejected; no verification bypass or plaintext fallback occurs; valid controls succeed. | `curl`/TLS scanner output, certificate fingerprints/config, edge/outbound logs with secrets removed. | Restore valid certificates/routes and remove test CA. | Security Lead |
| SEC-04 | Secret loading. Drill **D-FAIL-CLOSED**. | Start each applicable service with a missing secret file, unreadable file, permissive mode, malformed/empty value, and forbidden environment fallback; include the rootful runtime socket check. | Startup/doctor fails before readiness with an actionable non-secret error; secrets never appear in logs/process arguments; no insecure default is generated. Valid protected files are the control. | File names/modes (never contents), doctor/start exit/output, readiness and redacted process/log inspection. | Restore correct owner/mode/files, rotate any test secret, start services. | Operations Lead |
| SEC-05 | Presigned URL. Automated mapping `backend/core/tests/test_kubernetes_runner.py::test_transfer_rejects_unsafe_urls`; drill **D-FAIL-CLOSED**. | Exercise HTTP, credentials-in-URL, alternate scheme/host, modified key/query, excessive TTL, reuse after expiry, and staging URL from analyzer; include a valid short-lived control. | Unsafe URLs are rejected; generated URLs use HTTPS, approved host/key scope and configured short TTL; tampering/expiry fails; analyzer never receives staging URLs. | Pytest output, URL metadata with signatures/query redacted, request status/access logs, job spec, TTL/config evidence. | Expire/revoke URLs and delete test objects. | Security Lead |
| SEC-06 | Model allowlist/private fallback. Automated mapping `backend/core/tests/test_ai_gateway.py::test_endpoint_requires_explicit_allowlist`; drill **D-FAIL-CLOSED**. | Configure unlisted host, redirect, DNS rebinding/private-address mismatch, invalid TLS, unavailable allowed endpoint, and disallowed model ID; monitor a public canary endpoint. | Each request is rejected or fails closed; redirects are not followed; no public/external fallback or canary connection occurs; no model request is sent for a disallowed ID. | Pytest output, redacted gateway responses/logs, allowlist/model config, DNS/TLS evidence, canary access log and egress counters. | Restore approved endpoint/model config; remove canary records. | AI Security Lead |

**D-FAIL-CLOSED:** first prove a valid control succeeds, change exactly one trust
condition, attempt the operation, confirm denial plus absence of side effects or
fallback traffic, restore the condition, and prove the control succeeds again.
Configuration snapshots must contain hashes or redacted values rather than
secrets, bearer tokens, cookies, or URL signatures.

## Recovery and change-management checks

| ID | Check and mapping | Prerequisites and procedure | Expected outcome | Retained evidence | Cleanup | Pass/fail owner |
|---|---|---|---|---|---|---|
| REC-01 | Backup restoration. Supporting automated mapping `backend/core/tests/test_backup.py::test_backup_encryption_round_trip_and_tamper_detection`; drill **D-BACKUP-RESTORE**. | Populate both tenants with known scans/findings/audit events and objects; record DB/object manifest and audit checkpoint. Run `sh bin/trishulctl backup`, independently snapshot bucket bytes, then restore onto a clean compatible disposable VM with the separately held key. | Checksums/authenticated decryption, DB restore, compatible migrations, audit verification, and readiness pass; row counts/relationships and object SHA-256 values equal the checkpoint; both tenants can access only their own restored data. | Pytest output, commands/timestamps/exit codes, encrypted backup/checksum metadata, image/schema versions, pre/post manifests, audit verification, readiness and tenant smoke-test output. Do not retain the key. | Destroy restored VM and test backup per retention policy; securely remove temporary key copy and test objects. | Disaster Recovery Owner |
| UPG-01 | Failed-upgrade rollback. Drill **D-UPGRADE-ROLLBACK**. | Clone production-like pilot data to a disposable VM; take and verify a backup; stage signed current and candidate images. Inject failures separately at image replacement/readiness and at a backward-compatible migration checkpoint. | Upgrade health gate fails and reports the stage; documented rollback restores prior image digests/config and a ready service without lost/corrupt data. Schema remains compatible and audit/object manifests match. If compatibility cannot be proven, restore backup rather than starting old code. | Bundle signature/digests, backup verification, injected-fault record, upgrade/rollback output, Compose/schema before/after, readiness, row/object/audit checksums and elapsed time. | Remove disposable VM/bundles/test backup according to retention; revoke temporary credentials. | Change Manager |

**D-BACKUP-RESTORE:** perform restoration without access to the source database,
verify the encrypted backup before restore, restore bucket bytes at the same
checkpoint, run audit verification, compare manifests, and exercise authenticated
read-only API access as both tenants. **D-UPGRADE-ROLLBACK:** use the supported
upgrade command and health gate, never hand-edit migration history, capture the
failure before rollback, select image rollback only when schema compatibility is
documented, otherwise use the verified backup, and repeat readiness and integrity
checks after rollback.

## Release sign-off

The Release Manager verifies that every ID in this version appears exactly once
in `results.csv`, every result is **PASS**, each evidence link opens for the named
owner, cleanup is recorded, and no secret or customer source entered the evidence
bundle. Security signs TEN-01 through SEC-06, Operations signs RES-01 through
RES-05 and SEC-04, and the remaining named owners sign their checks. The Release
Manager then records final approval, candidate image digests, specification
version, commit, and evidence-bundle SHA-256. Any **FAIL**, missing owner,
incomplete evidence, or incomplete cleanup blocks pilot release.
