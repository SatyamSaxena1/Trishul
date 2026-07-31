#!/usr/bin/env python3
"""Validate private pilot ledgers and the controlled release manifest."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPAQUE_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def fail(message: str) -> None:
    raise ValueError(message)


def timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        fail(f"{field} must be an ISO-8601 timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc


def require_keys(value: dict, keys: set[str], field: str) -> None:
    missing = keys - value.keys()
    if missing:
        fail(f"{field} missing: {', '.join(sorted(missing))}")


def validate_ledger(path: Path) -> None:
    data = json.loads(path.read_text())
    require_keys(data, {"schema_version", "tenant_id", "repository_id", "approved_at", "executions"}, "ledger")
    if data["schema_version"] != 1:
        fail("unsupported ledger schema_version")
    for key in ("tenant_id", "repository_id"):
        if not isinstance(data[key], str) or not OPAQUE_ID.fullmatch(data[key]):
            fail(f"{key} must be an opaque identifier")
    timestamp(data["approved_at"], "approved_at")
    seen: set[str] = set()
    for index, run in enumerate(data["executions"]):
        label = f"executions[{index}]"
        require_keys(
            run,
            {
                "execution_id",
                "repository_version",
                "submitted_at",
                "completed_at",
                "outcome",
                "runtime_ms",
                "events",
                "versions",
                "findings_by_rule",
                "review",
                "incident_refs",
            },
            label,
        )
        if run["execution_id"] in seen:
            fail(f"duplicate execution_id: {run['execution_id']}")
        seen.add(run["execution_id"])
        start, end = (
            timestamp(run["submitted_at"], f"{label}.submitted_at"),
            timestamp(run["completed_at"], f"{label}.completed_at"),
        )
        if end < start or not isinstance(run["runtime_ms"], int) or run["runtime_ms"] < 0:
            fail(f"{label} has invalid completion or runtime")
        if run["outcome"] not in {"completed", "failed", "cancelled", "timed_out"}:
            fail(f"{label} has invalid terminal outcome")
        require_keys(run["versions"], {"release", "analyzer", "rule_pack"}, f"{label}.versions")
        for event in run["events"]:
            require_keys(event, {"type", "occurred_at", "actor", "reason"}, f"{label}.event")
            if event["type"] not in {"retry", "manual_recovery"}:
                fail(f"{label} has invalid recovery event")
            timestamp(event["occurred_at"], f"{label}.event.occurred_at")
        for finding in run["findings_by_rule"]:
            require_keys(finding, {"rule_id", "rule_version", "count"}, f"{label}.finding")
            if not isinstance(finding["count"], int) or finding["count"] < 0:
                fail(f"{label} has invalid finding count")
        review = run["review"]
        require_keys(review, {"completed", "reviewer", "completed_at"}, f"{label}.review")
        if review["completed"] is not True or not review["reviewer"]:
            fail(f"{label} review is incomplete")
        timestamp(review["completed_at"], f"{label}.review.completed_at")
        if any(not isinstance(ref, str) or not OPAQUE_ID.fullmatch(ref) for ref in run["incident_refs"]):
            fail(f"{label} incident references must be opaque IDs")


def validate_release(path: Path) -> None:
    data = json.loads(path.read_text())
    require_keys(
        data,
        {"schema_version", "release_version", "analyzer_version", "source_commit", "repairs", "approvals", "rollback"},
        "release",
    )
    if data["schema_version"] != 1:
        fail("unsupported release schema_version")
    for index, repair in enumerate(data["repairs"]):
        label = f"repairs[{index}]"
        require_keys(repair, {"acceptance_criterion", "summary", "regression_commands", "components"}, label)
        if not re.fullmatch(r"AC-[0-9]+", repair["acceptance_criterion"]):
            fail(f"{label} must identify an AC-N acceptance criterion")
        if not repair["regression_commands"] or not all(
            isinstance(item, str) and item.strip() for item in repair["regression_commands"]
        ):
            fail(f"{label} must include regression coverage")
    require_keys(data["approvals"], {"engineering", "security", "pilot_operations"}, "approvals")
    rollback = data["rollback"]
    require_keys(rollback, {"last_known_good_release", "conditions", "procedure", "schema_compatibility"}, "rollback")
    if not rollback["conditions"] or not all(isinstance(item, str) and item.strip() for item in rollback["conditions"]):
        fail("rollback must contain measurable conditions")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("ledger", "release"))
    parser.add_argument("path", type=Path, nargs="?")
    args = parser.parse_args()
    path = args.path or ROOT / "release/pilot-release-manifest.json"
    try:
        (validate_ledger if args.kind == "ledger" else validate_release)(path)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"invalid {args.kind}: {exc}", file=sys.stderr)
        return 1
    print(f"valid {args.kind}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
