# AI Trishul

AI Trishul is a multi-tenant GRC and deployment-assurance platform connecting evidence-backed code review, human-verified threat modeling, audit-firm engagements, compliance operations, and deterministic risk prioritization. It supports shared SaaS, isolated enterprise SaaS, and customer-hosted deployment models.

## Implemented MVP

- Django/DRF modular API with explicit RBAC/ABAC permission identifiers.
- Tenant-scoped ORM, PostgreSQL row-level security, composite tenant foreign keys, and cross-tenant tests.
- OIDC JWT validation with MFA claim enforcement and hashed, expiring service tokens.
- Immutable evidence/version models and a hash-chained, database-protected audit ledger.
- Safe ZIP/TAR inventory with traversal, link, file-count, file-size, and expansion limits.
- Disposable rootless OCI analyzer jobs with no network, read-only root, quotas, and signed image pinning in production.
- Experimental Python language pack using deterministic AST rules; model output cannot confirm findings.
- Structured STRIDE threat generation requiring human-verified components and flows.
- Evidence-required assessment conclusions and independent risk-acceptance approval.
- Deterministic, versioned risk scoring with retained inputs.
- Deployment Assurance: Terraform/Kubernetes/Compose/inventory normalization, a signed 20-rule control pack, blocker-first gate decisions, scoped time-bound exceptions, OSCAL assessment-results export, and a CI gate client that fails closed.
- SaaS operations: platform, audit-firm, and auditee tenant types; engagement-only cross-tenant access; server-side entitlements and usage; UCF-backed controls, evidence, gaps, risks, tasks, and locked auditor verdicts.
- Provider-neutral AI gateway with endpoint allowlisting, TLS validation, secret redaction, structured output validation, and no fallback.
- Static React/TypeScript OIDC interface served by the TLS edge container.
- Docker Compose deployment, encrypted backup/restore, offline release bundling, health checks, metrics, and upgrade tooling.
- Kubernetes/OpenShift enterprise profile with Kustomize, restricted pod security, network policy, autoscaling, disruption budgets, external secrets, and Kubernetes-native isolated analysis jobs.

The Python language pack is intentionally marked `experimental` until representative first-customer repositories establish its precision, recall, framework coverage, and maintenance acceptance.

## Development

For browser development without an OIDC provider, use the debug-only [local authentication setup](docs/local-development.md).

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
7. Install the deployment control pack with `docker compose exec api python manage.py bootstrap_assurance TENANT_SLUG`.

See [operations](docs/operations.md), [AWS shared-SaaS reference](deploy/aws/README.md), [enterprise deployment](docs/enterprise-deployment.md), [security model](docs/security.md), [architecture](docs/architecture.md), and [deployment assurance](docs/deployment-assurance.md).
