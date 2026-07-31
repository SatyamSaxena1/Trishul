# Customer-hosted operations

This page is the entry point for the supported single-host Docker Compose profile. The
step-by-step operator procedures are in the [Compose runbook](runbooks/compose.md).
They cover preparation, provisioning, installation, bootstrap, restart, backup,
restore, upgrade and rollback, diagnostics, resource and dependency incidents,
security containment, and pilot-data deletion.

## Supported MVP profile

- One supported Linux server or VM with at least 4 CPU cores, 12 GiB RAM, and 50
  GiB local disk, plus object-storage capacity.
- Docker Engine with Compose v2 and a separate, dedicated rootless Docker or Podman
  socket for analyzer jobs.
- Customer-managed DNS, TLS certificate, OIDC application, S3-compatible storage,
  and private model endpoints.
- PostgreSQL and Redis supplied by the Compose profile.

Analyzer concurrency and resource ceilings must be calibrated to the customer host.
The later Kubernetes/OpenShift profile is documented in
[enterprise deployment](enterprise-deployment.md); do not apply the Compose commands
to that profile.

## Operator entry points

Run commands from the checked-out release directory. `sh bin/trishulctl doctor`
validates configuration, secret permissions, the rootless runtime socket, Compose
configuration, and minimum free space. `install` starts services and health-gates
readiness. `backup`, `restore`, and `upgrade` implement the coordinated database
workflows described in the runbook.

Service endpoints are:

- `/api/v1/health/live` for process liveness.
- `/api/v1/health/ready` for database, queue, and object-store readiness.
- `/api/v1/metrics`, protected by `X-Metrics-Token` and not exposed through the
  edge proxy.

Ship structured container logs only to an approved destination. Alert on repeated
authorization failures, RLS denials, audit-chain failures, export spikes, unavailable
object storage, queue depth, stale job leases, analyzer failures, AI policy rejection,
disk pressure, and backup failure.
