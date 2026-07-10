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

## Architectural decisions

- Hybrid Python backend/static TypeScript frontend; no production Node backend.
- Modular monolith rather than business microservices.
- PostgreSQL RLS and relationship edges instead of separate tenant, search, and graph databases.
- Redis/Celery rather than a custom queue.
- Customer S3-compatible object storage rather than application filesystems.
- HTML/JSON reporting before a PDF renderer.
- Rootless OCI isolation; a rootful Docker socket is never accepted.
