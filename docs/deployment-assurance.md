# Deployment Assurance

Deployment Assurance turns an infrastructure change into an evidence-backed,
enforceable compliance decision. A proposed deployment (a Terraform plan, a
Kubernetes manifest set, a Compose file) or an observed one (a collected
inventory) is normalized, evaluated against a signed policy pack, scored on the
platform's existing risk model, and either approved or blocked — with every
input, verdict and reason retained as immutable evidence.

It is a module inside the existing modular monolith, not a separate product. It
reuses the platform's tenancy, RBAC, evidence, audit, risk-scoring, approval and
worker-isolation machinery rather than duplicating any of it.

## The pipeline

```text
artifact ──► normalize ──► evaluate ──► score ──► decide ──► record
             (canonical    (registered   (shared   (blockers   (immutable,
              resources)     rules)       risk      first)      hashed
                                          model)                evidence)
```

1. **Normalize.** The artifact is parsed under hard structural bounds into the
   canonical resource envelope (`trishul-resource/1.0`). One envelope means a
   rule written once applies to Terraform, Kubernetes, Compose and live
   inventory alike.
2. **Evaluate.** Every registered rule runs against every resource in sorted
   order. Output is deterministic: same snapshot + same pack + same engine
   produces a byte-identical `results_hash`.
3. **Score.** Each unwaived failure is scored through `core.risk.calculate` —
   the same versioned formula used for code findings — and enters the risk
   register with its inputs retained.
4. **Decide.** Blocker rules are evaluated **before** the aggregate score, so a
   single critical failure cannot be averaged away.
5. **Record.** Source artifact, normalized snapshot, result manifest and
   decision envelope are each hashed and stored as immutable evidence.

## Decision semantics

| Condition (evaluated in order) | Decision |
| --- | --- |
| Evaluation error on a production or internet-exposed target | `error` (fails closed) |
| Evaluation error elsewhere | `manual_review` |
| Any unwaived blocking-rule failure | `blocked` |
| Any unwaived critical failure on a protected target | `blocked` |
| Aggregate risk ≥ block threshold (default 70) | `blocked` |
| Aggregate risk ≥ review threshold (default 50) | `manual_review` |
| Any outstanding manual-review control | `manual_review` |
| Aggregate risk ≥ actions threshold (default 25), or any open failure | `approved_with_actions` |
| Otherwise | `approved` |

Aggregate risk is the highest residual priority plus one tenth of the next four.
Averaging would let one critical finding vanish into a large clean plan; summing
would make any large deployment look catastrophic.

Thresholds live in a versioned `DecisionThresholdProfile`. Tailoring them
produces a new version, so a historical decision always resolves to the exact
profile that produced it.

## The shipped control pack

`trishul-baseline@1.0.0` — twenty deterministic rules. Blocking rules are marked
**B**.

| Rule | Concern | |
| --- | --- | --- |
| `DA-NET-001` | SSH/RDP/WinRM open to the internet | **B** |
| `DA-NET-002` | Database port or instance publicly reachable | **B** |
| `DA-ENC-001` | Sensitive storage unencrypted at rest | **B** |
| `DA-STOR-001` | Object storage permits public access | **B** |
| `DA-SEC-001` | Plaintext credential in the artifact | **B** |
| `DA-VULN-001` | Unwaived critical/exploitable vulnerability | **B** |
| `DA-OS-001` | Operating system past the supported baseline | **B** |
| `DA-LOG-001` | Audit logging provisioned but disabled | **B** |
| `DA-LOG-002` | Logs not centralized, or retention too short | |
| `DA-IAM-001` | Wildcard action *and* resource grant | **B** |
| `DA-K8S-001` | Privileged container or host-equivalent capability | **B** |
| `DA-K8S-002` | Host namespace sharing or sensitive `hostPath` | **B** |
| `DA-K8S-003` | Container runs as root | **B** |
| `DA-K8S-004` | No CPU/memory limits | |
| `DA-K8S-005` | Writable container root filesystem | |
| `DA-K8S-006` | Privilege escalation not disabled | |
| `DA-SUPPLY-001` | Image referenced by mutable tag | |
| `DA-BACKUP-001` | Missing or short backup retention | |
| `DA-TLS-001` | TLS minimum below 1.2 | **B** |
| `DA-CONFIG-001` | Unauthenticated instance metadata (IMDSv1) | |

Two conventions run through the pack:

- **Environment-aware severity, not environment-aware truth.** A rule reports
  the same fact everywhere; only the consequence varies, and only through
  declared target facts. A root container fails in production and warns in
  development.
- **Unknown is not pass.** An opaque IAM document or a missing encryption
  attribute yields `manual_review`, never a silent pass. A resource type no rule
  claims is counted in `unevaluated_resource_types`, not treated as compliant.

## Framework traceability

Each rule declares mappings to NIST SP 800-53 Rev. 5, CIS Controls v8.1,
ISO/IEC 27002:2022 and PCI DSS v4.0.1, surfaced in the OSCAL export.

**These are traceability, not certification.** A mapping asserts that the rule
produces evidence *relevant to* a control. It does not assert that passing the
rule satisfies the control: SP 800-53 is a control catalogue, ISO/IEC 27001 is a
management-system standard, and PCI DSS scopes to cardholder-data environments.
A human assessor still owns the compliance conclusion. Mappings must be reviewed
against the exact framework editions a customer has adopted.

## Exceptions

A waiver is bound to a target, a rule **version**, and a resource fingerprint,
and it expires. Any of those changing invalidates it — so a narrow approval can
never silently widen, and a rule whose logic changed retires the exceptions
written against its previous behaviour.

Requesting and approving are separate permissions, self-approval is refused at
both the model and the view layer, and service accounts may do neither. Expiry
is automatic (`expire_waivers`, every 15 minutes): a waiver that had to be
renewed by hand would in practice become permanent.

## Determinism and reproducibility

Every run records `input_hash`, `policy_hash`, `engine_versions` and a
`results_hash`. A rule may not perform I/O, read settings, touch the ORM, or
consult the clock except through its context — anything that could vary between
runs must arrive as a recorded input.

`results_hash` deliberately excludes the run identifier so two evaluations of
the same snapshot under the same pack are provably identical. `decision_hash`
deliberately includes it, so two decisions remain distinguishable.

A pack is content-addressed over its full rule definitions. Modifying a rule
without bumping the pack version is refused by `bootstrap_assurance`, because
historical decisions reference that hash.

## Evidence, and the limit of the guarantee

Four artifacts are retained per run: source artifact, normalized snapshot,
result manifest, decision envelope. Each carries a SHA-256 and a provenance
envelope, indexed in PostgreSQL and stored in the object store. Evidence rows
are append-only, enforced by a database trigger.

A hash recorded beside the object it describes proves the object has not changed
*relative to a hash you trust*. An adversary who can rewrite both the object and
the database row defeats it. Detecting that requires the checkpoint to leave the
system — see the exported audit-checkpoint procedure in
[operations](operations.md). This module produces the hashes and envelopes that
make such a checkpoint meaningful; it does not by itself make storage
tamper-proof.

## Handling sensitive artifacts

A Terraform plan can contain secret values even when the CLI redacts its console
output. Consequently:

- plans are classified confidential and encrypted at rest;
- the gate client never prints artifact content, and the example workflow never
  publishes the plan as a CI artifact;
- detected secrets are recorded as a location plus a digest — **never** the
  value — so a compliance record cannot itself become a credential leak;
- rule failures echo only bounded, redacted attributes, and a rule that raises
  reports its exception *type* only, since a message can carry artifact
  fragments.

## Setup

```text
# once per tenant, after bootstrap_tenant
python manage.py bootstrap_assurance <tenant-slug>
```

This installs the pack, its rules and their framework mappings, a default
threshold profile and a default policy profile. Re-running an unchanged release
is a no-op.

Then register a target and wire the gate:

```text
POST /api/v1/assurance/deployment-targets/
POST /api/v1/assurance/deployment-snapshots/                 (multipart artifact)
POST /api/v1/assurance/deployment-snapshots/{id}/evaluations/
GET  /api/v1/assurance/evaluation-runs/{id}/decision/
GET  /api/v1/assurance/evaluation-runs/{id}/oscal-results/
```

`bin/trishul-gate` performs that sequence and uses a stable exit contract: `0`
for `approved` and, by default, `approved_with_actions`; `1` for `blocked`; `2`
for `manual_review`; `3` for timeout; and `4` for service, authentication,
malformed-response, or integrity failure. `--actions-require-review` maps
`approved_with_actions` to `2`; `--warn-only` reports but suppresses a non-zero
exit during shadow rollout. Every unexpected state fails closed. See
[`docs/examples/github-deployment-gate.yml`](examples/github-deployment-gate.yml)
for the consumer workflow.

Roll out with `--warn-only` first, confirm blocking-rule precision on real
changes, then remove the flag and mark the check required.

## Permissions

| Permission | Granted to |
| --- | --- |
| `deployment_target.read` / `.write` | read: most roles; write: architect, appsec |
| `deployment_snapshot.submit` | appsec, developer (and CI service accounts) |
| `deployment_evaluation.create` / `.read` | appsec, developer |
| `deployment_decision.read` | all roles including executive |
| `deployment_exception.request` | appsec, manager |
| `deployment_exception.approve` | CISO only |
| `deployment_policy.manage` | administrators |
| `deployment_evidence.read` | CISO, appsec, assessor, auditor |

Machines submit; humans decide. A service account may submit artifacts and read
decisions, but never approve an exception, accept risk, or manage policy — and
that boundary is enforced in the viewset, so an over-scoped token is a
non-event rather than an exploit.

## Known gaps

Deliberately out of scope for this slice, in rough priority order:

1. **No GitHub App / Check Run.** The gate is an exit code today. Rich
   annotations and expected-source branch protection need a GitHub App.
2. **OSCAL export only.** Catalog and Profile *import*, full POA&M generation,
   and complete SSP generation are not implemented.
3. **No live connectors.** `DriftEvent` is modelled and migrated but nothing
   populates it; AWS Config, Azure Resource Graph and Cloud Asset Inventory
   collection are the next increment.
4. **No remediation execution.** `automation_class` is recorded per rule; no
   patch generation or approval-gated execution exists yet.
5. **No presigned upload.** Artifacts use a bounded multipart POST (25 MiB),
   which is sufficient for typical plans but not for very large inventories.
