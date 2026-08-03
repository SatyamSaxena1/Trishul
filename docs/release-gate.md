# Release acceptance gate

Every production release candidate is **NO-GO by default**. A release owner must assemble a JSON evidence manifest, have an independent approver review it, and run:

```text
python scripts/release_gate.py release-evidence.json --output release-decision.json
```

Exit code `0` and `"decision": "GO"` are both required. Exit code `1`, malformed input, missing evidence, an empty denominator, or any failed mandatory check means **NO-GO**. Do not waive, round, reinterpret, or lower a target in the manifest. A target change requires a separately reviewed change to this policy and the gate implementation; it cannot unblock the candidate being evaluated.

Store the manifest, decision, and referenced verification artifacts with the immutable release record. Evidence must be redacted, access-controlled, and safe to distribute to release reviewers. Every evidence entry has:

```json
{
  "artifact": "acceptance/job-summary.json",
  "description": "Redacted aggregate output from the acceptance run",
  "sha256": "64-lowercase-or-uppercase-hexadecimal-characters",
  "contains_sensitive_data": false
}
```

The digest binds the manifest to the reviewed artifact. Never attach source, secrets, tokens, tenant content, personal data, or unredacted logs.

## Mandatory criteria and formulas

1. **Representative repositories:** `repositories` contains at least ten unique repository IDs. Each must have `analyzed: true` and an immutable `version` (normally a commit SHA). Select repositories before testing and document why their languages, frameworks, sizes, ownership, and deployment patterns represent the supported population. Attach `repository_evidence`.
2. **Reliable valid-job completion:** include every attempted job in `jobs`. Mark a job `valid: false` only for a documented input that is outside the supported contract; never exclude infrastructure or analyzer failures. The formula is `valid jobs with completed=true and manual_recovery=false / all valid jobs`. It must be at least `0.95`, using the unrounded value and a non-empty denominator. Attach `job_evidence`.
3. **Finding provenance:** every item in `findings` must contain non-empty `file`, positive integer `line`, `rule`, `evidence`, `analyzer_version`, and `repository_version` values. There must be at least one finding. Attach `provenance_evidence` showing an exported finding can be traced back to the analyzed immutable repository version and analyzer version.
4. **Reviewed-finding usefulness:** reviewers set `reviewed: true` and record `useful` as a boolean. Usefulness is `reviewed findings with useful=true / all reviewed findings`. It must be at least `0.70`, using the unrounded value and a non-empty denominator. A finding is useful when it correctly identifies an actionable security or assurance concern, or supplies relevant evidence that materially advances a reviewer decision; duplicate, incorrect, unactionable, or irrelevant results are not useful. Define and freeze the review sample before review, retain reviewer decisions, and attach `review_evidence`.
5. **Protected critical failures:** `failures` records acceptance failures with `id`, `category`, `severity`, and `status`. No critical failure in `security`, `tenant-isolation`, `backup`, or `data-loss` may remain in a status other than `resolved` or `closed`. Attach `failure_evidence`, including a redacted zero-open-critical report even when the list is empty.
6. **Operational demonstrations:** `demonstrations` must contain `installation`, `restoration`, and `rollback`; each requires `successful: true` and its own evidence. Perform them against the candidate artifacts in a production-like clean environment. Restoration must validate data and audit integrity, while rollback must verify the prior compatible release and retained data—not merely that a command returned zero.

## Blocker fixes

Record every fix made for a release blocker in `blocker_fixes`. Each entry must include:

* a stable `id`;
* a non-empty `regression_tests` list whose entries record the exact `command` and `passed: true`;
* a non-empty `acceptance_checks_rerun` list naming every affected check with `passed: true`; and
* one or more non-sensitive evidence entries in `evidence`.

A failed test/check, absent rerun, or missing/sensitive evidence makes the candidate NO-GO. Add new fixes rather than deleting the history of earlier attempts.

## Minimal manifest shape

```json
{
  "repositories": [{"id": "service-a", "version": "commit-sha", "analyzed": true}],
  "repository_evidence": [],
  "jobs": [{"id": "job-1", "valid": true, "completed": true, "manual_recovery": false}],
  "job_evidence": [],
  "findings": [{"id": "F-1", "file": "src/a.py", "line": 12, "rule": "PY-1", "evidence": "redacted excerpt", "analyzer_version": "1.2.3", "repository_version": "commit-sha", "reviewed": true, "useful": true}],
  "provenance_evidence": [],
  "review_evidence": [],
  "failures": [],
  "failure_evidence": [],
  "demonstrations": {
    "installation": {"successful": true, "evidence": []},
    "restoration": {"successful": true, "evidence": []},
    "rollback": {"successful": true, "evidence": []}
  },
  "blocker_fixes": []
}
```

The empty evidence arrays above illustrate placement only; they must contain valid evidence entries for an actual GO decision. The ten-repository minimum is likewise intentionally not expanded in this abbreviated example.
