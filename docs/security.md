# Security model

## Trust rules

Repository files, comments, documents, evidence, model responses, and retrieved content are untrusted data. They cannot authorize actions, approve compliance, confirm vulnerabilities, change risk, or invoke arbitrary tools.

## Tenant isolation

Tenant isolation is enforced three times:

1. Authentication selects only a tenant for which the principal has membership or service scope.
2. Tenant-aware managers and serializers fail closed and reject cross-tenant relations.
3. PostgreSQL forces RLS and composite `(id, tenant_id)` foreign keys on tenant-owned tables.

Every new tenant-owned model must be added to the RLS and relationship migration tests. Direct use of `all_objects` is restricted to audited system paths that establish tenant context first. `scripts/verify_postgres_security.py` exercises fail-closed RLS, cross-tenant composite-key rejection, and immutability triggers against real PostgreSQL in CI for both `core` and `deployment_assurance`.

Deployment decisions are content-immutable but not row-frozen: a database trigger rejects any change to the decision, its scores, reasons, or hash, while leaving the supersession pointer writable so a later evaluation can retire an earlier verdict. Evidence rows are strictly append-only.

## Identity

Production accepts OIDC access tokens with signature, issuer, audience, expiry, subject, and MFA claim validation. Users receive no tenant membership automatically. Service tokens are random, hashed at rest, scoped, expiring, revocable, and shown once.

## AI boundary

Only the AI gateway receives endpoint credentials and model-network access. Endpoint hostnames require an explicit allowlist, TLS and hostname validation are mandatory, redirects are rejected, common secrets are redacted, messages are bounded, and output must satisfy the requested JSON Schema. Private endpoint failure never causes external fallback.

## Deployment artifact boundary

Terraform plans, Kubernetes manifests, Compose files, and collected inventories are untrusted data on the same terms as repository content. Parsing is bounded before it begins: a 25 MiB artifact ceiling, document/depth/node caps, a 20,000-resource ceiling, and outright refusal of YAML aliases, which are the billion-laughs vector and expand inside the composer before any size check could apply.

Plans can contain secret values even when the CLI redacts its console output. Artifacts are therefore classified confidential, encrypted at rest, and never echoed: detected secrets are recorded as a location plus a SHA-256 digest and never the value, rule output carries only bounded redacted attributes, and a rule that raises reports its exception type rather than its message.

Deployment artifact normalization runs through the existing analysis-controller queue inside the same disposable analyzer boundary used for repository analysis. The analyzer receives a read-only input volume and a separate writable output volume; it has no network, service-account token, application, cloud, remediation, or model credentials.

## Analysis boundary

The controller refuses `/var/run/docker.sock` operationally. It uses a dedicated rootless runtime account and launches analyzer images by digest outside development. Job containers receive one repository archive and one output volume, no network, no application/database/model secrets, and bounded CPU, memory, PIDs, storage, and time.

On Kubernetes, the controller has namespace-scoped permission only to create, read, and delete Jobs and scratch PVCs. Separate staging and collection Jobs use short-lived presigned object URLs; the analyzer Job receives neither URLs nor service-account credentials and is selected by an explicit no-network policy. Access to Job specifications must remain limited because staging URLs are usable until their short expiry.

The MVP never runs repository scripts, builds, tests, package installation, or dependency hooks.

## Known residual risks

- A single Linux host remains one availability and kernel-security boundary.
- A compromised application process may misuse its database role within its granted tenant context.
- The experimental language pack is not a claim of broad language coverage.
- Object-store byte backup and retention remain customer-owned; AI Trishul backs up database state and exports an integrity manifest.
- Hash chaining detects audit modification but requires exported checkpoints to detect a privileged database replacement.

## Threat-model checklist

- Tenant context is cleared at request and reused-transaction boundaries; absent context fails closed.
- Audit-firm visibility requires an active, in-date engagement plus an active assigned member and object scope. A tenant relationship alone grants nothing.
- Entitlements and quotas are enforced in backend actions; the UI is informational only.
- YAML aliases, unsafe constructors, excessive documents/nodes/depth/resources, archive traversal, links, decompression expansion, and oversized uploads are rejected before evaluation.
- Rule ordering and hash inputs are canonical and deterministic; unknown facts never receive pass credit.
- Evidence, logs, metrics, and gate output omit secret values and sensitive Terraform content.
- Analyzer input is read-only, output is isolated, networking is disabled, privileges are dropped, storage and runtime are bounded, and cleanup failure is observable.
- Decision/evidence/auditor records are database-protected against mutation; exception self-approval is rejected.
- SSRF, open redirect, token replay, service-account human actions, and frontend-only authorization are rejected at backend trust boundaries.
