# Customer-hosted operations

## Supported MVP profile

- One supported Linux server or VM.
- Docker Compose v2 and a separate rootless Docker/Podman socket for analyzer jobs.
- Customer-managed DNS, TLS certificate, OIDC application, S3-compatible storage, and private model endpoints.
- PostgreSQL and Redis supplied by the Compose profile.

Production should reserve at least 4 CPU cores, 12 GiB RAM, and 50 GiB local disk plus object-storage capacity. Analyzer concurrency and resource ceilings must be calibrated to the customer host.

## Installation

Run `sh bin/trishulctl doctor` before every first installation or host change. It rejects missing configuration, weak secret-file permissions, missing rootless runtime sockets, rootful socket paths, invalid Compose configuration, and inadequate disk.

`sh bin/trishulctl install` starts migrations first, waits on dependency health, starts stateless services, and requires application readiness before success.

## Backup and restore

`sh bin/trishulctl backup` temporarily stops writes, creates a PostgreSQL custom-format dump, encrypts it with AES-256-GCM using `secrets/backup_key`, exports an object/audit manifest, and writes checksums under `backups/`.

The customer must independently back up the S3-compatible bucket at the same checkpoint and retain the backup encryption key separately.

Restore only onto a clean compatible deployment:

```text
sh bin/trishulctl restore backups/20260710T120000Z --confirm-restore
```

Restore verifies checksums and authenticated encryption, restores PostgreSQL, applies compatible migrations, verifies audit chains, starts services, and waits for readiness. Exercise restore at least quarterly.

## Upgrade

`sh bin/trishulctl upgrade` creates a backup, obtains signed versioned images, runs forward migrations, replaces stateless services, and health-gates completion. Database changes must follow expand/contract rules. Image rollback is allowed only while the migrated schema remains backward compatible.

## Offline release

`RELEASE_SIGNING_KEY=/secure/key.pem sh bin/trishulctl bundle` saves every required OCI image, Compose/configuration files, operational tooling, documentation, SHA-256 checksums, a signature, and the release public key. Verify the signature and checksums before loading images in the restricted environment.

## Observability

- `/api/v1/health/live`: process liveness.
- `/api/v1/health/ready`: database, queue, and object-store readiness.
- `/api/v1/metrics`: protected by `X-Metrics-Token` and not exposed through the edge proxy.
- Container logs are structured and must be shipped without source, evidence, prompts, responses, or secrets.

Alert on repeated authorization failures, RLS denials, audit-chain failures, export spikes, unavailable object storage, queue depth, stale job leases, analyzer failures, AI budget/policy rejection, disk pressure, and backup failure.

## Tenant-safe operational reporting

Generate a JSON report for one tenant and a half-open UTC time window:

```text
python backend/manage.py generate_tenant_report \
  --tenant 01234567-89ab-cdef-0123-456789abcdef \
  --since 2026-07-01T00:00:00Z --until 2026-08-01T00:00:00Z > report.json
```

The UUID is mandatory; there is no all-tenant mode. The generator uses explicitly tenant-filtered persisted repository-version, scan, job, finding, finding-review, and audit-event records. "Submitted" means repository versions created in the window; "successfully analyzed" means those versions have a completed scan. Completion rate is completed jobs divided by all jobs submitted in the window. Manual recovery is conservatively represented by terminal jobs with more than one attempt. Runtime uses job creation through its last persisted update and reports linearly interpolated p50/p90/p95/p99 values. Rates are `null` when their denominator is zero.

Record finding decisions in `FindingReview`, including the controlled outcome, optional usefulness decision, and unresolved-blocker flag. Free-text feedback is counted but never emitted. Record incident audit actions as `incident.security` or `incident.operational`. Record drills as `drill.backup`, `drill.restore`, `drill.installation`, or `drill.rollback`, with `details.result` set to `passed`, `failed`, `partial`, or `not_run`. Unknown drill results are reported only as `unspecified`.

The output contains counts, controlled rule IDs/error codes, rates, and durations. It deliberately excludes repository names and paths, source, raw evidence, audit actors/resources and arbitrary audit details, secrets, prompts, model requests/responses, finding text, and reviewer feedback text. Do not join those fields into this report. Customer approval for identifiable or content-bearing material requires a separate, purpose-specific export and authorization review; this command intentionally has no override.

The later Kubernetes/OpenShift profile, including installation and recovery contracts, is documented in [enterprise deployment](enterprise-deployment.md). Compose remains the supported MVP profile.
