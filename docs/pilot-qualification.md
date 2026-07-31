# Pilot qualification runbook

Use this runbook for the supported single-VM Compose profile. It is an acceptance test, not a substitute for the installation and security runbooks. Run it from a version-controlled release checkout with an operator and an independent witness. Never put credentials, tokens, repository contents, object names, user subjects, or customer hostnames in the report.

## Preconditions and evidence rules

Use a clean supported Linux VM with at least 4 online CPU cores, 12 GiB RAM, 50 GiB local disk, Compose v2, and a dedicated rootless OCI socket. Provision test OIDC and S3-compatible services that are disposable but operationally equivalent to the pilot services. Prepare releases `N-1` and `N`; their schema transition must be documented as backward compatible before testing image rollback.

Create a report from the template below. For every step record UTC start/end, elapsed time, release digest, result, operator interventions, discrepancies, and sanitized evidence. Acceptable evidence includes command exit status, readiness status, aggregate row/object counts, hashes, audit checkpoint hashes, and opaque test identifiers. Do not record command lines containing secrets. A witness must confirm destructive actions and restore selection.

## 1. Clean install

1. Record OS/kernel, online CPU count, memory, free disk, Compose version, and the source revision. Confirm there are no Trishul containers, networks, or volumes.
2. Configure `.env`, secret files, TLS, test OIDC, test object storage, and the rootless analyzer runtime as described in the installation runbook. Record secret file modes only.
3. Run `sh bin/trishulctl doctor` and `sh bin/trishulctl install`. Record both durations and `docker compose ps` health, then bootstrap two tenants with one MFA-capable test user in each. Do not record subjects or email addresses.
4. Confirm the HTTPS readiness endpoint succeeds and that HTTP/plain or invalid TLS access is rejected. A prerequisite or readiness failure stops the test.

## 2. Synthetic scan and baseline

Use a non-sensitive synthetic repository fixture whose expected findings and content SHA-256 are release-controlled. Through the same API/UI path used by an operator, upload it to tenant A, start a scan, wait for completion, and create a review decision on one finding. Record the repository/version opaque IDs, fixture hash, analyzer image digest, scan state, aggregate expected/actual finding counts, review count, object count, and audit checkpoint. Do not use a customer repository.

Verify that the repository version is immutable and that a second upload creates a new version. Log in as tenant B and verify list, detail, export, review, and any guessed-ID requests cannot reveal or alter tenant A data. Record status codes and zero leaked-item counts, not tokens or response bodies.

## 3. Coordinated checkpoint

Quiesce writes and keep them quiesced until both state stores are checkpointed. Run `sh bin/trishulctl backup`; while services are stopped, use the object-store runbook to create a versioned bucket snapshot. Record the database backup path, database manifest audit checkpoint, object snapshot ID, snapshot completion time, aggregate object count/bytes, and release manifest digest in one recovery-set record. Independently run `sha256sum -c SHA256SUMS`, validate the object snapshot, and confirm the separately held backup key is available. Any snapshot made outside the quiesced interval is not coordinated and must be repeated.

Resume services and perform one labelled post-checkpoint change. This proves the restore boundary: the change must be absent after restore while all checkpointed data remains present.

## 4. Isolation and clean restore

Stop the original deployment, revoke its ingress, and disable its service account and object-store write access. A witness confirms that its containers are stopped and its endpoint is unreachable. Preserve it until qualification finishes; do not allow it to share the restore database, bucket, networks, volumes, or credentials.

On a second clean compatible VM (or a demonstrably isolated clean deployment), install release `N-1` without bootstrapping data. Restore the versioned object snapshot into an empty bucket, then run:

```text
sh bin/trishulctl restore /approved/recovery-set/database --confirm-restore
```

Record checksum, authenticated-decryption, migration, audit verification, and readiness results. Re-enable ingress only after all verification below passes.

## 5. Recovery verification

Authenticate both test users with the required MFA claim and verify an absent or invalid MFA claim is rejected. Repeat the tenant A/B negative tests from step 2. Compare repository/version IDs and hashes, finding state/counts, review decisions, object hashes, and the checkpoint audit hash to the baseline. Run `docker compose run --rm migrate python manage.py verify_audit` and record success. Confirm the labelled post-checkpoint change is absent. Differences in checkpointed data, authorization, isolation, or audit integrity fail qualification.

## 6. Controlled failed upgrade and rollback

Create and verify a fresh coordinated checkpoint. Confirm release `N-1` readiness, then deliberately configure one release `N` application image reference to a nonexistent digest. This failure is safe because it occurs before migrations; do not simulate failure with a destructive migration. Run `sh bin/trishulctl upgrade` and require a non-zero exit. Record the injected condition, phase, duration, and sanitized error, then restore every image reference to the recorded `N-1` digest and run `docker compose up -d --remove-orphans` followed by the readiness check.

If an upgrade failure occurs after migrations start, rollback is permitted only when the release manifest explicitly says the schema remains compatible with `N-1`; otherwise restore the coordinated recovery set into clean services.

Repeat authentication, tenant isolation, repository/version, findings, reviews, object hash, and audit checks. Create and scan a second synthetic version and add a review to prove `N-1` remains writable. Compare all checkpointed counts/hashes and record that no checkpointed data was lost.

## 7. Discrepancies and reruns

Stop at the first unsafe discrepancy. Record observed/expected behavior and the step where it occurred. Correct the product or applicable written runbook in a reviewed change, reset to the last clean boundary, and rerun the failed step plus every dependent verification. Preserve both failed and passing attempt records. Environmental shortfalls are blockers, not waived failures.

## Qualification report template

```text
Report ID / date (UTC):
Operator / witness roles:
Non-sensitive environment summary:
Source revision and N-1/N image digests:
Recovery-set ID (database + object snapshot + release manifest):

Step | attempt | UTC start/end | duration | result | intervention | evidence
-----|---------|---------------|----------|--------|--------------|---------

Baseline and restored aggregate counts/hashes:
Authentication and tenant-isolation negative-test results:
Audit checkpoint and verify_audit result:
Failure injected and observed failure phase:
Rollback release/readiness/write-test result:
Discrepancies, corrections, and dependent steps rerun:
Residual risks or blockers:
Operator conclusion / witness confirmation:
```
