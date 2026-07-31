import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "validate_pilot_controls.py"
SPEC = importlib.util.spec_from_file_location("validate_pilot_controls", SCRIPT)
controls = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(controls)


def valid_execution():
    return {
        "execution_id": "run-1",
        "repository_version": "sha256:0123456789abcdef",
        "submitted_at": "2026-07-31T10:00:00Z",
        "completed_at": "2026-07-31T10:01:00Z",
        "outcome": "completed",
        "runtime_ms": 60_000,
        "events": [],
        "versions": {"release": "1.0.0", "analyzer": "1.0.0", "rule_pack": "python-1"},
        "findings_by_rule": [{"rule_id": "PY-001", "rule_version": "1", "count": 2}],
        "review": {"completed": True, "reviewer": "reviewer-7", "completed_at": "2026-07-31T11:00:00Z"},
        "incident_refs": ["INC-42"],
    }


def write_json(tmp_path, value):
    path = tmp_path / "record.json"
    path.write_text(json.dumps(value))
    return path


def test_ledger_accepts_complete_tenant_record(tmp_path):
    path = write_json(
        tmp_path,
        {
            "schema_version": 1,
            "tenant_id": "tenant-7",
            "repository_id": "repo-9",
            "approved_at": "2026-07-31T09:00:00Z",
            "executions": [valid_execution()],
        },
    )

    controls.validate_ledger(path)


def test_ledger_rejects_incomplete_review(tmp_path):
    execution = valid_execution()
    execution["review"]["completed"] = False
    path = write_json(
        tmp_path,
        {
            "schema_version": 1,
            "tenant_id": "tenant-7",
            "repository_id": "repo-9",
            "approved_at": "2026-07-31T09:00:00Z",
            "executions": [execution],
        },
    )

    with pytest.raises(ValueError, match="review is incomplete"):
        controls.validate_ledger(path)


def test_release_rejects_fix_without_regression_coverage(tmp_path):
    manifest = json.loads((Path(__file__).resolve().parents[3] / "release/pilot-release-manifest.json").read_text())
    manifest["repairs"] = [
        {
            "acceptance_criterion": "AC-12",
            "summary": "Repair timeout",
            "regression_commands": [],
            "components": ["worker"],
        }
    ]

    with pytest.raises(ValueError, match="regression coverage"):
        controls.validate_release(write_json(tmp_path, manifest))
