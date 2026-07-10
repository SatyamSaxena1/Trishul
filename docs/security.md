# Security model

## Trust rules

Repository files, comments, documents, evidence, model responses, and retrieved content are untrusted data. They cannot authorize actions, approve compliance, confirm vulnerabilities, change risk, or invoke arbitrary tools.

## Tenant isolation

Tenant isolation is enforced three times:

1. Authentication selects only a tenant for which the principal has membership or service scope.
2. Tenant-aware managers and serializers fail closed and reject cross-tenant relations.
3. PostgreSQL forces RLS and composite `(id, tenant_id)` foreign keys on tenant-owned tables.

Every new tenant-owned model must be added to the RLS and relationship migration tests. Direct use of `all_objects` is restricted to audited system paths that establish tenant context first.

## Identity

Production accepts OIDC access tokens with signature, issuer, audience, expiry, subject, and MFA claim validation. Users receive no tenant membership automatically. Service tokens are random, hashed at rest, scoped, expiring, revocable, and shown once.

## AI boundary

Only the AI gateway receives endpoint credentials and model-network access. Endpoint hostnames require an explicit allowlist, TLS and hostname validation are mandatory, redirects are rejected, common secrets are redacted, messages are bounded, and output must satisfy the requested JSON Schema. Private endpoint failure never causes external fallback.

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
