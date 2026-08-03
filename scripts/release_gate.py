#!/usr/bin/env python3
"""Evaluate a Trishul release-candidate evidence manifest.

The gate is deliberately fail closed: missing or malformed evidence is a NO-GO.
It only reads the supplied manifest and never modifies the acceptance target.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

MIN_REPOSITORIES = 10
MIN_COMPLETION = 0.95
MIN_USEFULNESS = 0.70
PROVENANCE_FIELDS = ("file", "line", "rule", "evidence", "analyzer_version", "repository_version")
PROTECTED_FAILURE_CATEGORIES = {"security", "tenant-isolation", "backup", "data-loss"}
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _evidence_valid(item: Any) -> bool:
    return (
        isinstance(item, dict)
        and isinstance(item.get("artifact"), str)
        and bool(item["artifact"].strip())
        and isinstance(item.get("description"), str)
        and bool(item["description"].strip())
        and isinstance(item.get("sha256"), str)
        and SHA256.fullmatch(item["sha256"]) is not None
        and item.get("contains_sensitive_data") is False
    )


def _has_evidence(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_evidence_valid(item) for item in value)


def evaluate(manifest: Any) -> dict[str, Any]:
    """Return a stable, machine-readable GO/NO-GO decision."""
    checks: list[dict[str, Any]] = []

    def check(identifier: str, passed: bool, detail: str) -> None:
        checks.append({"id": identifier, "passed": bool(passed), "detail": detail})

    if not isinstance(manifest, dict):
        check("manifest", False, "manifest must be a JSON object")
        return {"decision": "NO-GO", "checks": checks}

    repositories = manifest.get("repositories", [])
    analyzed = (
        [
            repo
            for repo in repositories
            if isinstance(repo, dict)
            and repo.get("analyzed") is True
            and isinstance(repo.get("id"), str)
            and repo["id"].strip()
            and isinstance(repo.get("version"), str)
            and repo["version"].strip()
        ]
        if isinstance(repositories, list)
        else []
    )
    repository_ids = {repo["id"] for repo in analyzed}
    check(
        "representative-repositories",
        len(repository_ids) >= MIN_REPOSITORIES and _has_evidence(manifest.get("repository_evidence")),
        f"{len(repository_ids)} unique, versioned repositories analyzed; minimum is {MIN_REPOSITORIES}",
    )

    jobs = manifest.get("jobs", [])
    valid_jobs = (
        [job for job in jobs if isinstance(job, dict) and job.get("valid") is True] if isinstance(jobs, list) else []
    )
    completed = sum(job.get("completed") is True and job.get("manual_recovery") is False for job in valid_jobs)
    completion = completed / len(valid_jobs) if valid_jobs else 0.0
    check(
        "valid-job-completion",
        bool(valid_jobs) and completion >= MIN_COMPLETION and _has_evidence(manifest.get("job_evidence")),
        f"{completed}/{len(valid_jobs)} valid jobs completed without manual recovery "
        f"({completion:.2%}); minimum is 95%",
    )

    findings = manifest.get("findings", [])
    findings = findings if isinstance(findings, list) else []
    missing = [
        str(finding.get("id", index)) if isinstance(finding, dict) else str(index)
        for index, finding in enumerate(findings)
        if not isinstance(finding, dict)
        or any(field not in finding or finding[field] in (None, "") for field in PROVENANCE_FIELDS)
        or not isinstance(finding.get("line"), int)
        or finding.get("line", 0) < 1
    ]
    check(
        "finding-provenance",
        bool(findings) and not missing and _has_evidence(manifest.get("provenance_evidence")),
        "all findings have file, positive line, rule, evidence, analyzer version, and repository version"
        if not missing
        else f"findings with incomplete provenance: {', '.join(missing)}",
    )

    reviewed = [finding for finding in findings if isinstance(finding, dict) and finding.get("reviewed") is True]
    useful = sum(finding.get("useful") is True for finding in reviewed)
    usefulness = useful / len(reviewed) if reviewed else 0.0
    check(
        "reviewed-finding-usefulness",
        bool(reviewed) and usefulness >= MIN_USEFULNESS and _has_evidence(manifest.get("review_evidence")),
        f"{useful}/{len(reviewed)} reviewed findings were useful ({usefulness:.2%}); minimum is 70%",
    )

    failures = manifest.get("failures", [])
    failures = failures if isinstance(failures, list) else []
    unresolved = [
        str(failure.get("id", index))
        for index, failure in enumerate(failures)
        if isinstance(failure, dict)
        and failure.get("category") in PROTECTED_FAILURE_CATEGORIES
        and str(failure.get("severity", "")).lower() == "critical"
        and str(failure.get("status", "")).lower() not in {"resolved", "closed"}
    ]
    check(
        "critical-failures",
        not unresolved and _has_evidence(manifest.get("failure_evidence")),
        "no unresolved protected critical failures"
        if not unresolved
        else f"unresolved critical failures: {', '.join(unresolved)}",
    )

    demonstrations = manifest.get("demonstrations", {})
    demos_ok = isinstance(demonstrations, dict) and all(
        isinstance(demonstrations.get(name), dict)
        and demonstrations[name].get("successful") is True
        and _has_evidence(demonstrations[name].get("evidence"))
        for name in ("installation", "restoration", "rollback")
    )
    check(
        "operational-demonstrations",
        demos_ok,
        "installation, restoration, and rollback must each succeed with evidence",
    )

    fixes = manifest.get("blocker_fixes", [])
    fixes = fixes if isinstance(fixes, list) else []
    bad_fixes = [
        str(fix.get("id", index))
        for index, fix in enumerate(fixes)
        if not isinstance(fix, dict)
        or not isinstance(fix.get("regression_tests"), list)
        or not fix["regression_tests"]
        or not all(
            isinstance(test, dict) and test.get("command") and test.get("passed") is True
            for test in fix["regression_tests"]
        )
        or not isinstance(fix.get("acceptance_checks_rerun"), list)
        or not fix["acceptance_checks_rerun"]
        or not all(
            isinstance(item, dict) and item.get("check") and item.get("passed") is True
            for item in fix["acceptance_checks_rerun"]
        )
        or not _has_evidence(fix.get("evidence"))
    ]
    check(
        "blocker-fix-verification",
        not bad_fixes,
        "every blocker fix has passing regression coverage, rerun acceptance checks, and non-sensitive evidence"
        if not bad_fixes
        else f"unverified blocker fixes: {', '.join(bad_fixes)}",
    )

    return {"decision": "GO" if all(item["passed"] for item in checks) else "NO-GO", "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate mandatory Trishul release criteria")
    parser.add_argument("manifest", type=Path, help="release evidence JSON manifest")
    parser.add_argument("--output", type=Path, help="write the decision JSON to this path")
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = evaluate(manifest)
    except (OSError, json.JSONDecodeError) as exc:
        result = {"decision": "NO-GO", "checks": [{"id": "manifest", "passed": False, "detail": str(exc)}]}
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if result["decision"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
