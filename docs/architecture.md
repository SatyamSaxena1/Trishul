# Architecture

The repository uses one backend ecosystem. Django/DRF, Celery workers, the scheduler, analysis controller, and AI gateway are Python processes built from one application image. React is compiled to static assets; Node.js is not present in production.

## Runtime boundaries

- `edge`: TLS, static assets, CSP, rate limiting, and API reverse proxy.
- `api`: tenant-aware control plane with no OCI runtime access.
- `worker` and `scheduler`: idempotent asynchronous workflows.
- `ai-gateway`: the only service attached to the model-egress network or model credentials.
- `analysis-controller`: consumes only the analysis queue and uses a dedicated rootless runtime socket under Compose or least-privilege Job/PVC APIs under Kubernetes.
- analyzer jobs: disposable containers with no network, no capabilities, bounded resources, and no application secrets.
- PostgreSQL: authoritative domain, job, policy, and audit state.
- Redis: transient Celery transport; lost messages are recovered from PostgreSQL job state.
- S3-compatible storage: repository versions, evidence, and reports outside application containers.

## Kubernetes compatibility

Services are stateless, configured through environment variables or secret files, use external persistence and queues, expose health/metrics endpoints, accept graceful termination, and run as non-root with read-only roots. The enterprise Kustomize profile maps these images to Deployments, horizontally scaled workers, ingress/Route, external secrets, network policy, autoscaling, and disruption budgets. PostgreSQL, Redis, object storage, ingress, and centralized observability remain customer-operated enterprise services.

## Modules

`core` owns tenancy, identity, evidence, assessments, risk, and the audit ledger. `deployment_assurance` adds pre-deployment and live-state control evaluation on top of those primitives; it defines its own models, permissions, and routes (`/api/v1/assurance/`) while reusing the existing analysis-controller queue and isolation boundary. It depends on `core` in one direction only. See [deployment assurance](deployment-assurance.md).

A module owns its permission vocabulary; `core` owns the role-to-permission mapping and folds module grants in at import. That keeps `core` free of a hard dependency on any module a given deployment may not install.

## Architectural decisions

- Hybrid Python backend/static TypeScript frontend; no production Node backend.
- Modular monolith rather than business microservices.
- PostgreSQL RLS and relationship edges instead of separate tenant, search, and graph databases.
- Redis/Celery rather than a custom queue.
- Customer S3-compatible object storage rather than application filesystems.
- HTML/JSON reporting before a PDF renderer.
- Rootless OCI isolation; a rootful Docker socket is never accepted.

## Shared SaaS topology

The AWS reference provisions a two-AZ VPC, private EKS and data subnets, EKS, multi-AZ RDS PostgreSQL, serverless Valkey, versioned KMS-encrypted S3, Secrets Manager references, WAF, and an operations topic. Tenant rows share these services in the shared tier but remain isolated through scoped ORM access, forced PostgreSQL RLS, and same-tenant composite foreign keys. Enterprise tenants move to separate database, bucket, and KMS resources; dedicated/private deployments retain the customer-hosted topology. The executable foundation and the account-specific integration gaps are listed in [the AWS reference](../deploy/aws/README.md).
