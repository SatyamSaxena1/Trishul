# AI Trishul

AI Trishul is a customer-hosted security intelligence MVP connecting evidence-backed code review, human-verified threat modeling, evidence-based assessments, and deterministic risk prioritization.

## Implemented MVP

- Django/DRF modular API with explicit RBAC/ABAC permission identifiers.
- Tenant-scoped ORM, PostgreSQL row-level security, composite tenant foreign keys, and cross-tenant tests.
- OIDC JWT validation with MFA claim enforcement and hashed, expiring service tokens.
- Immutable evidence/version models and a hash-chained, database-protected audit ledger.
- Safe ZIP/TAR inventory with traversal, link, file-count, file-size, and expansion limits.
- Signed GitHub/GitLab webhooks, exact-commit fetching, encrypted provider credentials, and replay protection.
- Disposable rootless OCI analyzer jobs with no network, read-only root, quotas, and signed image pinning in production.
- Experimental Python AST rules plus offline Semgrep source and Trivy dependency/secret/configuration packs.
- Signed CI test and staging-only OWASP ZAP result ingestion; external tools cannot confirm findings.
- Structured STRIDE threat generation requiring human-verified components and flows.
- Evidence-required assessment conclusions and independent risk-acceptance approval.
- Deterministic, versioned risk scoring with retained inputs.
- Provider-neutral AI gateway with endpoint allowlisting, TLS validation, secret redaction, structured output validation, and no fallback.
- Static React/TypeScript OIDC interface served by the TLS edge container.
- Docker Compose deployment, encrypted backup/restore, offline release bundling, health checks, metrics, and upgrade tooling.
- Kubernetes/OpenShift enterprise profile with Kustomize, restricted pod security, network policy, autoscaling, disruption budgets, external secrets, and Kubernetes-native isolated analysis jobs.

The scanner packs are intentionally marked `experimental` until representative customer repositories establish their precision, recall, framework coverage, and maintenance acceptance. Trishul never installs dependencies or executes repository code; builds, project tests, and staging DAST remain in customer CI.

## Development

```text
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
cd frontend && npm ci && npm test && npm run build
```

On Windows, replace `.venv/bin` with `.venv/Scripts`.

## Customer-hosted installation

1. Copy `.env.example` to `.env` and configure customer endpoints.
2. Create the files documented in `secrets/README.md` with mode `0600`.
3. Configure a dedicated rootless Docker or Podman API socket for the analysis controller.
4. Build or load the signed release images.
5. Run `sh bin/trishulctl doctor`, then `sh bin/trishulctl install`.
6. Bootstrap the first OIDC subject with `sh bin/trishulctl bootstrap SUBJECT EMAIL TENANT_SLUG "Tenant Name"`.

See [operations](docs/operations.md), [enterprise deployment](docs/enterprise-deployment.md), [security model](docs/security.md), and [architecture](docs/architecture.md).
