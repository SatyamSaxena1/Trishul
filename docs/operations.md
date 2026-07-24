# Customer-hosted operations

## Supported MVP profile

- One supported Linux server or VM.
- Docker Compose v2 and a separate rootless Docker/Podman socket for analyzer jobs.
- Customer-managed DNS, TLS certificate, OIDC application, S3-compatible storage, and private model endpoints.
- PostgreSQL and Redis supplied by the Compose profile.

Production with the multi-stack analyzer should reserve at least 8 CPU cores, 24 GiB RAM, and 150 GiB local disk plus object-storage capacity. Start with one analyzer and two Git fetches at a time; analyzer concurrency and resource ceilings must be calibrated to the customer host.

GitHub and GitLab webhooks enter through repository-specific URLs returned by the repository API. The repository fetcher is the only application service with Git-provider egress and private Git credential decryption. Semgrep and Trivy run in the existing networkless analyzer boundary; project builds, tests, package installation, and OWASP ZAP remain CI responsibilities.

Register Git repositories through `POST /api/v1/repositories/` with `source_type`, HTTPS `clone_url`,
provider `external_id`, `webhook_secret`, and `ci_secret`. GitHub also requires `installation_id`; GitLab
requires an expiring project token in `credential`. Configure provider webhooks at
`/api/v1/webhooks/{github|gitlab}/{tenant_id}/{repository_id}`. The GitHub App needs repository contents
read and commit statuses write permissions. Keep the GitLab clone token limited to `read_repository`;
optionally supply a separate, expiring Reporter token as `status_credential` when direct-fetch scans must
publish advisory GitLab commit statuses. GitLab CI uploads already report their own advisory job status.

CI service accounts need `repository.read`, `repository.import`, `scan.read`, and `scan.create`, scoped to
their application. Copy the applicable template under `deploy/ci/`; CI uploads the commit archive, queues
Semgrep and Trivy, and may submit signed `ci-tests` and `zap` bundles. Register and approve each exact
staging origin through `/api/v1/staging-targets/` before accepting ZAP evidence. The included ZAP
automation policy is unauthenticated, capped at 30 minutes and five active requests per second, and enables
only read-only discovery/TLS rules.

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

The later Kubernetes/OpenShift profile, including installation and recovery contracts, is documented in [enterprise deployment](enterprise-deployment.md). Compose remains the supported MVP profile.
