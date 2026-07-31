# Analyst code-review workflow

The analyzer supplies deterministic leads for human review; it does not confirm that
a weakness is exploitable and an empty result is not evidence that a repository is
secure.

## Pilot procedure

1. Before accepting an archive, compare the repository with the
   [Python analyzer pilot support matrix](analyzer-support-matrix.md), including its
   archive limits, supported call shapes, and known blind spots.
2. Confirm the scan used language pack `python-stdlib` version `1.0`. Do not describe
   other languages, frameworks, library versions, file types, or rules as covered.
3. Review `analyzed_python_files`, `unsupported_files`, and `parse_failures`. Escalate
   unexpected counts and manually review relevant skipped content before drawing a
   conclusion.
4. Validate each `needs_validation` finding in source context. Confirm name binding,
   runtime configuration, attacker influence, reachability, and compensating controls.
5. Record false positives, false negatives found by manual review, and unsupported
   constructs as pilot feedback. Treat PY003 and the HTTPX surface of PY002 as
   experimental, as specified by the matrix.
6. Report conclusions with the exact pack version, rule IDs, reviewed scope, skipped
   files, and manual-review limitations. Never translate “no findings” into “secure,”
   “fully scanned,” or framework support beyond the matrix.
