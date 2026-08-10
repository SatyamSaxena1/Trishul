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

## Deployment Assurance runbooks

Install the policy pack once per tenant, and again after any release that publishes a new pack version:

```text
docker compose exec api python manage.py bootstrap_assurance <tenant-slug>
```

The command is idempotent and refuses to rewrite a pack whose content hash changed without a version bump, because completed decisions reference that hash. A modified rule requires a new pack version.

| Situation | Response |
| --- | --- |
| Evaluation backlog | Check `analysis-controller` health first; the queue backs a merge-blocking check, so a stalled controller stalls delivery. Scale replicas, then look for a single oversized artifact. |
| Policy regression after a release | Point the tenant's `PolicyProfile` back at the previous pack version. Completed decisions are preserved; re-run affected pull requests. Do not edit rules in place. |
| Gate unavailable during a deployment window | The gate fails closed by design. Break-glass is a branch-protection administrator override, which must raise a follow-up review task — never a change that makes the gate fail open. |
| Evidence hash mismatch | Freeze the affected target, stop approving against the affected material, and compare the exported audit checkpoint with object-store versions before drawing any conclusion. |
| Waiver pressure | Rising active-waiver counts on one rule usually mean the rule is miscalibrated, not that the risk is acceptable. Review the rule before renewing the waivers. |

Alert additionally on: Deployment Assurance jobs waiting on the shared analysis queue, evaluation p95 latency, evaluations ending in `failed`, an unexpected rise in `not_evaluated` outcomes (a normalizer no longer understands an artifact), blocking-rate deviation after a pack release, and waivers expiring within seven days.

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

### SaaS telemetry contract

The protected Prometheus endpoint supplies process/runtime metrics. SaaS signals are derived from structured request logs, audit events, usage rows, and scheduled database queries until dedicated counters are added. Aggregate by tenant type, isolation tier, decision, or reason code only; never use tenant IDs/names, emails, evidence text, resource paths, URLs, or secrets as labels.

| Signal | Source and safe dimensions |
| --- | --- |
| Requests and authentication failures | HTTP logs; route, status class, tenant type |
| Engagement and cross-tenant denials | `CrossTenantAccessEvent`; action, reason, decision |
| Queue depth, evaluation duration/decision, normalizer failure | Celery/run state; queue, source type, terminal decision, bounded error code |
| Analyzer cleanup and evidence-processing failures | structured job logs; runtime, bounded error code |
| RLS verification failures | CI/security job success gauge; environment only |
| Storage, AI, and quota usage/denials | `UsageRecord` and entitlement denial audit events; metric, plan code, reason |
| Expiring engagements, waivers, and evidence | scheduled count gauges; day bucket |
| Open critical gaps and stale remediation tasks | scheduled count gauges; severity/status and age bucket |

## Shared SaaS deployment

Apply [the AWS Terraform foundation](../deploy/aws/README.md), create the non-bypass `trishul_app` role, install the AWS Load Balancer Controller and External Secrets using workload identity, populate the empty runtime secret, and apply `deploy/kubernetes/base`. Attach the regional WAF ACL and ACM certificate to the public edge ALB. PostgreSQL, Valkey, S3, and metrics stay private. CloudFront, Route 53, SES identity, private EKS endpoint restrictions, and multi-region DR are integration steps and are not provisioned by this repository.

The shared tier uses one database and bucket with forced RLS and tenant-prefixed objects. The enterprise tier requires separate database, bucket, and KMS resources. The dedicated tier uses the customer-hosted Compose or Kubernetes profile. Moving a tenant between tiers is an operator-controlled export/import, not an in-place toggle.

## SaaS runbooks

### Disaster recovery

Restore the newest verified database snapshot and the matching versioned S3 checkpoint into a clean compatible environment, restore KMS/Secrets Manager access, apply migrations, run `scripts/verify_postgres_security.py`, verify the audit chain and object hashes, then expose traffic. DNS failover is manual in this MVP. The Terraform reference is multi-AZ, not multi-region; define customer RPO/RTO and test a full regional rebuild at least twice yearly.

### Key rotation

Rotate OIDC/service credentials and application secrets in Secrets Manager, wait for External Secrets rollout, restart the affected stateless workloads, and revoke the old value. Use RDS-managed rotation for the owner credential; rotate the application role separately. Enable KMS automatic rotation, and re-encrypt only where policy requires a new key rather than a new key version. Preserve old backup keys for the full backup-retention window.

### Tenant suspension, export, deletion, and retention

Suspension sets `Tenant.is_active=false`, revokes service tokens, and closes active sessions; it does not delete evidence. Export through an authorized auditee/platform workflow to a tenant-scoped encrypted archive containing database records, object versions, and an audit checkpoint. Verify counts and hashes before delivery.

Deletion is a two-person operator procedure: suspend, export if contractually required, wait the configured retention/legal-hold period, delete tenant-prefixed object versions, then delete database rows in dependency order under owner context and record an external deletion certificate. Shared backup copies age out under backup retention and cannot promise immediate physical erasure; disclose that before deletion. There is no self-service hard-delete endpoint in this release.

### Incident response and analyzer compromise

For an incident, suspend affected principals/tenants, revoke tokens and URLs, preserve logs and immutable audit checkpoints, isolate affected workloads, rotate reachable credentials, determine tenant/object scope, notify according to the incident plan, rebuild from signed images, and verify RLS/audit/object hashes before reopening.

If an analyzer is suspected, stop the analysis controller, delete active Jobs/containers and scratch volumes, revoke still-live staging URLs, quarantine the image digest and submitted artifact, rotate the object-store signing credential, inspect controller/runtime audit logs, rebuild from a trusted digest, and run a known-safe canary. The analyzer holds no application/cloud/model secret and has no network, limiting blast radius; treat the controller/runtime boundary as affected until proven otherwise.

### Engagement revocation and audit integrity

Set an engagement to `revoked` or `closed`, record the reason/status history, deactivate its assignments, and revoke firm service tokens if any were issued. Database and API authorization deny the next access immediately; no cache invalidation is required. Preserve all decisions, verdicts, and evidence under the auditee retention policy.

Run `python manage.py verify_audit` after restore, before regulated exports, and during incident investigation. Compare the result with a checkpoint stored outside the platform trust boundary; an internal hash chain alone cannot detect replacement of both rows and hashes.

## Schema migration, feature disable, and rollback

Back up PostgreSQL and object storage at one checkpoint before upgrade. Migrate in dependency order: existing `core` migrations, `core.0005` SaaS/UCF tables and additive tenant columns, `core.0006` RLS/composite-key/immutability security, `deployment_assurance.0003` GRC links, then `deployment_assurance.0004` engagement-read policies. Existing flat tenants become shared-tier `auditee` tenants; the blank legacy auditee mode preserves their behavior, and existing organizations, workspaces, applications, evidence, and Deployment Assurance rows retain their IDs and ownership.

The schema phase adds nullable or defaulted columns and new tables first. Constraint creation and RLS enable/force take table locks, so schedule the migration in a maintenance window and drain writes. Existing rows need no data backfill beyond database defaults. Unique `(id, tenant_id)` parent keys are created before the deferrable composite foreign keys; RLS policies are installed only after the columns/tables and relationship function exist.

For rollback, stop new traffic and workers, retain all data, and redeploy the previous image only if its code is compatible with the expanded schema. Prefer feature disable: remove Deployment Assurance routes/navigation and stop new evaluations while leaving its tables, evidence, gaps, risks, and tasks intact. Do not reverse the security migrations or drop SaaS/UCF data in place. If incompatible behavior or destructive migration has occurred, restore the pre-upgrade database and matching object-store checkpoint into a clean environment; replaying newer writes is not supported.

## Known gaps by severity

- **Critical:** none known after the implemented isolation and integrity checks; production onboarding still requires an independent security review.
- **High:** the AWS foundation is single-region; private EKS endpoint enforcement and enterprise/dedicated tenant provisioning are not automated; audit checkpoints require an external immutable destination operated outside this trust boundary.
- **Medium:** no live cloud drift connectors, GitHub App/Check Run, presigned large-artifact upload, OSCAL Catalogue/Profile import, complete SSP/POA&M generation, or approval-gated remediation execution; SaaS domain metrics are currently derived rather than native counters.
- **Low:** CloudFront, Route 53, SES/ACM setup, tenant tier migration, and deletion orchestration are documented operator procedures rather than one-command workflows.

The recommended next phase is the high-priority isolation/DR work: automate enterprise database/bucket/KMS provisioning, private EKS access, external immutable audit checkpoints, and a tested cross-region restore. Commercial billing, complete TPRM campaigns/vendor portal, full policy authoring, OCR, and vector search remain explicitly out of scope.

The later Kubernetes/OpenShift profile, including installation and recovery contracts, is documented in [enterprise deployment](enterprise-deployment.md). Compose remains the supported MVP profile.
