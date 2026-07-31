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

The metrics endpoint exposes deployment-wide, low-cardinality series only. Job series include submitted and terminal
counts (`outcome` is limited to `completed`, `failed`, or `cancelled`), execution-duration and queue-wait histograms,
active/stale gauges, retry/recovery totals, and broker depth for only `default` and `analysis`. It also exposes analyzer
failures split into `failure` and `timeout`, AI gateway failures as a separate series, host-available bytes, latest
backup age and checksum-verification result, and object-store readiness. A queue depth of `-1` means the broker could
not be queried. No metric label or value contains a tenant/workspace/application name, repository or evidence path,
evidence, prompt/response content, model endpoint, object key, error message, credential, or secret. Do not add such
labels when extending metrics; labels must come from a reviewed fixed enumeration.

### Pilot alert thresholds

These defaults assume at most five concurrent pilot-sized scans and an 1,800-second analyzer deadline. Alert only
after the stated duration to avoid paging on scrape or scheduling jitter.

| Condition | Warning | Critical |
| --- | --- | --- |
| Analysis queue depth | `>5` for 10 min | `>10` for 10 min |
| Queue wait | p95 `>5 min` for 15 min | p95 `>15 min` for 15 min |
| Job duration | p95 `>20 min` for 15 min | p95 `>30 min` or any timeout for 5 min |
| Active jobs | `>5` for 5 min | `>5` for 15 min (concurrency/lease fault) |
| Stale jobs | `>=1` for 2 min | `>=3` for 5 min |
| Retries/recoveries | increase `>=2` in 15 min | increase `>=5` in 15 min |
| Analyzer failures | increase `>=2` in 30 min | increase `>=5` in 30 min or 3 consecutive scans |
| AI failures | increase `>=3` in 15 min | increase `>=10` in 15 min; deterministic scans remain usable |
| Available host disk | `<15 GiB` for 10 min | `<10 GiB` for 5 min (new scans/backups must stop) |
| Backup age | `>25 h` | `>48 h` |
| Backup verification | latest result `0` | result `0` for 1 h or no verified backup |
| Object store | readiness `0` for 2 min | readiness `0` for 10 min |
| API readiness | failing for 2 min | failing for 10 min |

### Alert response

1. **Queue, wait, active, or stale:** check `docker compose ps` and the scheduler/controller logs; confirm the
   `analysis` worker is consuming, then inspect CPU, memory, rootless-runtime health, and expired leases. Do not raise
   concurrency above five until capacity is confirmed. Reconciliation automatically requeues fewer than three
   attempts; repeated recovery requires operator investigation rather than manual duplicate submission.
2. **Analyzer failure or timeout:** correlate by timestamp and opaque job ID in restricted logs, check analyzer image
   health and resource ceilings, and retry only after the cause is corrected. Never paste source/evidence into tickets.
3. **AI failure:** check the private endpoint, TLS, rate/budget policy, and gateway logs. Keep this separate from
   deterministic analyzer incidents; deterministic results can continue while AI workflows are disabled.
4. **Disk:** pause new scans, identify container/runtime or backup growth with host tools, retain required backups,
   and expand or safely reclaim capacity. Never delete the only verified recovery set.
5. **Backup:** run `sh bin/trishulctl backup`, confirm `verification.status` is `success`, verify the coordinated
   customer object-store checkpoint, and escalate immediately if verification fails. Perform a clean restore drill
   at least quarterly.
6. **Object store/readiness:** check endpoint DNS/TLS, credentials, bucket policy/capacity, PostgreSQL, and Redis as
   indicated by `/health/ready`; restore service before resuming writes. Do not print credentials during diagnosis.

The later Kubernetes/OpenShift profile, including installation and recovery contracts, is documented in [enterprise deployment](enterprise-deployment.md). Compose remains the supported MVP profile.
