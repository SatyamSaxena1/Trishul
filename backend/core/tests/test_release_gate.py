from scripts.release_gate import evaluate

HASH = "a" * 64


def evidence(name="report.json"):
    return [
        {
            "artifact": name,
            "description": "redacted verification output",
            "sha256": HASH,
            "contains_sensitive_data": False,
        }
    ]


def passing_manifest():
    finding = {
        "id": "F-1",
        "file": "app.py",
        "line": 3,
        "rule": "PY-1",
        "evidence": "safe excerpt",
        "analyzer_version": "1.0.0",
        "repository_version": "abc123",
        "reviewed": True,
        "useful": True,
    }
    return {
        "repositories": [{"id": f"repo-{i}", "version": f"sha-{i}", "analyzed": True} for i in range(10)],
        "repository_evidence": evidence(),
        "jobs": [{"valid": True, "completed": True, "manual_recovery": False} for _ in range(20)],
        "job_evidence": evidence(),
        "findings": [finding],
        "provenance_evidence": evidence(),
        "review_evidence": evidence(),
        "failures": [],
        "failure_evidence": evidence(),
        "demonstrations": {
            name: {"successful": True, "evidence": evidence()} for name in ("installation", "restoration", "rollback")
        },
        "blocker_fixes": [],
    }


def test_all_mandatory_criteria_produce_go():
    assert evaluate(passing_manifest())["decision"] == "GO"


def test_thresholds_are_fail_closed_and_not_rounded_up():
    manifest = passing_manifest()
    manifest["repositories"] = manifest["repositories"][:9]
    manifest["jobs"] = [{"valid": True, "completed": True, "manual_recovery": False} for _ in range(18)] + [
        {"valid": True, "completed": False, "manual_recovery": False}
    ]
    manifest["findings"] = [{**manifest["findings"][0], "useful": i < 2} for i in range(3)]
    result = evaluate(manifest)
    failed = {item["id"] for item in result["checks"] if not item["passed"]}
    assert result["decision"] == "NO-GO"
    assert {"representative-repositories", "valid-job-completion", "reviewed-finding-usefulness"} <= failed


def test_missing_provenance_and_unresolved_critical_failure_are_no_go():
    manifest = passing_manifest()
    del manifest["findings"][0]["repository_version"]
    manifest["failures"] = [{"id": "SEC-9", "category": "tenant-isolation", "severity": "critical", "status": "open"}]
    failed = {item["id"] for item in evaluate(manifest)["checks"] if not item["passed"]}
    assert {"finding-provenance", "critical-failures"} <= failed


def test_blocker_fix_requires_regression_rerun_and_non_sensitive_evidence():
    manifest = passing_manifest()
    manifest["blocker_fixes"] = [
        {
            "id": "BUG-4",
            "regression_tests": [{"command": "pytest test_bug.py", "passed": True}],
            "acceptance_checks_rerun": [{"check": "restoration", "passed": True}],
            "evidence": [{**evidence()[0], "contains_sensitive_data": True}],
        }
    ]
    assert evaluate(manifest)["decision"] == "NO-GO"
