# Pilot execution and release controls

## Private execution ledger

The pilot operations owner must provision `PILOT_LEDGER_ROOT` on an encrypted,
access-controlled volume **outside this Git checkout**. The default local
convenience path, `pilot-ledger/`, is ignored by Git, but it is not an approved
production location. Grant access only to pilot operators and reviewers, use a
separate directory per tenant, and prohibit tenant names, repository names,
findings, and incident identifiers from tickets, release manifests, and public
source control.

Each approved repository has one JSON ledger document conforming to
`docs/schemas/pilot-ledger.schema.json`. Use opaque tenant and repository IDs in
file names. The document records:

- the immutable repository-version identifier (commit and/or archive SHA-256);
- submission and completion timestamps, terminal outcome, and runtime;
- every automated retry and manual-recovery event;
- analyzer, rule-pack, and product release versions;
- finding counts grouped by rule ID and rule version;
- review completion, reviewer, and timestamp; and
- references to incidents in the customer's private incident system.

An operator must validate a record before accepting a run:

```text
python scripts/validate_pilot_controls.py ledger "$PILOT_LEDGER_ROOT/tenant-id/repository-id.json"
```

Write records atomically (a same-filesystem temporary file followed by rename),
retain prior versions in write-once storage, and log access in the customer's
audit system. Never overwrite or delete an execution. Corrections are appended
as a manual-recovery event referencing the superseded execution. The reviewer
must reconcile finding totals with the scan output and close the review before
the repository's pilot result is reported. Incident references are opaque IDs,
not URLs, credentials, descriptions, or customer data.

## One controlled pilot release path

All pilot fixes use the following path; emergency fixes do not bypass it:

1. Triage the defect against a numbered pilot acceptance criterion. If it does
   not repair one, add it to the post-pilot backlog and do not include it.
2. Create the minimal fix and automated regression coverage that fails without
   the fix. Keep unrelated refactors and features out of the candidate.
3. Add the repair to `release/pilot-release-manifest.json`, including the exact
   acceptance-criterion ID, regression test commands, changed components, and
   measurable rollback conditions. Update release and analyzer versions.
4. Run every manifest regression command plus the normal test suite. Validate
   the manifest with `python scripts/validate_pilot_controls.py release`.
5. Obtain the named engineering, security, and pilot-operations approvals.
   Build and sign one candidate from the reviewed commit; never rebuild between
   approval and promotion.
6. Deploy to the pilot staging tenant, run acceptance and tenant-isolation
   checks, then promote the identical image digests during the approved window.
7. Observe the stated rollback signals. If any condition is met, stop new jobs,
   preserve ledger and incident evidence, execute the documented rollback, and
   record recovery events against affected executions.

Rollback instructions must name the last-known-good release, data/schema
compatibility constraints, stop conditions, and verification steps. A generic
"rollback on failure" statement is invalid. Release metadata contains only
opaque criterion IDs and no tenant data.

## Post-pilot backlog

Feature requests, optimizations, broad refactors, new integrations, and other
work that does not directly restore a failed pilot acceptance criterion are
labelled `post-pilot`, linked from the internal backlog, and excluded from pilot
branches, manifests, images, and deployment windows. The pilot owner reviews
that backlog only after pilot exit criteria have been accepted.
