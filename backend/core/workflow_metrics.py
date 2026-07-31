"""Low-cardinality, cross-tenant workflow aggregates for the Prometheus boundary."""

import math

from django.db.models import Count

from .models import Finding, Job, RepositorySubmission, Scan


def _line(name, value, labels=None):
    suffix = ""
    if labels:
        suffix = "{" + ",".join(f'{key}="{value}"' for key, value in labels.items()) + "}"
    return f"{name}{suffix} {value}\n"


def _seconds(rows, start, end):
    return sorted(
        (getattr(row, end) - getattr(row, start)).total_seconds()
        for row in rows
        if getattr(row, start) is not None and getattr(row, end) is not None
    )


def _percentile(values, quantile):
    if not values:
        return 0
    rank = (len(values) - 1) * quantile
    lower = math.floor(rank)
    upper = math.ceil(rank)
    return values[lower] if lower == upper else values[lower] + (values[upper] - values[lower]) * (rank - lower)


def render_workflow_metrics():
    """Render aggregates only; tenant/repository/user identifiers never become labels."""
    submissions = list(RepositorySubmission.all_objects.all())
    scans = list(Scan.all_objects.all())
    stages = {
        "submission_received": sum(item.received_at is not None for item in submissions),
        "archive_validation_started": sum(item.validation_started_at is not None for item in submissions),
        "archive_validation_completed": sum(item.validation_completed_at is not None for item in submissions),
        "analysis_queued": sum(item.analysis_queued_at is not None for item in scans),
        "analysis_started": sum(item.analysis_started_at is not None for item in scans),
        "analysis_terminated": sum(item.analysis_terminated_at is not None for item in scans),
        "findings_persisted": sum(item.findings_persisted_at is not None for item in scans),
        "first_analyst_review": sum(item.first_analyst_review_at is not None for item in scans),
        "final_review_outcome": sum(item.final_review_outcome_at is not None for item in scans),
        "risk_workflow_completed": sum(item.risk_workflow_completed_at is not None for item in scans),
    }
    output = ["# HELP trishul_workflow_stage_total Workflow transitions recorded across all tenants.\n"]
    output.append("# TYPE trishul_workflow_stage_total gauge\n")
    output.extend(_line("trishul_workflow_stage_total", count, {"stage": stage}) for stage, count in stages.items())
    for outcome in ("accepted", "rejected"):
        output.append(
            _line(
                "trishul_archive_validation_outcome_total",
                sum(item.validation_outcome == outcome for item in submissions),
                {"outcome": outcome},
            )
        )

    duration_pairs = {
        "archive_validation": (submissions, "validation_started_at", "validation_completed_at"),
        "queue_wait": (scans, "analysis_queued_at", "analysis_started_at"),
        "analysis_runtime": (scans, "analysis_started_at", "analysis_terminated_at"),
        "persistence": (scans, "analysis_started_at", "findings_persisted_at"),
        "time_to_first_review": (scans, "findings_persisted_at", "first_analyst_review_at"),
        "time_to_final_review": (scans, "findings_persisted_at", "final_review_outcome_at"),
        "risk_workflow": (scans, "final_review_outcome_at", "risk_workflow_completed_at"),
    }
    output.append("# TYPE trishul_workflow_duration_seconds gauge\n")
    for workflow, (rows, start, end) in duration_pairs.items():
        values = _seconds(rows, start, end)
        output.append(_line("trishul_workflow_duration_seconds", sum(values), {"workflow": workflow, "stat": "sum"}))
        output.append(_line("trishul_workflow_duration_seconds", len(values), {"workflow": workflow, "stat": "count"}))
        for name, quantile in (("p50", 0.5), ("p90", 0.9), ("p95", 0.95), ("p99", 0.99)):
            output.append(
                _line(
                    "trishul_workflow_duration_seconds",
                    _percentile(values, quantile),
                    {"workflow": workflow, "stat": name},
                )
            )

    outcomes = Finding.all_objects.values("status").annotate(total=Count("id"))
    output.append("# TYPE trishul_finding_review_outcome_total gauge\n")
    output.extend(
        _line("trishul_finding_review_outcome_total", row["total"], {"outcome": row["status"]}) for row in outcomes
    )
    completed = sum(scan.state == Scan.State.COMPLETED for scan in scans)
    failed = sum(scan.state == Scan.State.FAILED for scan in scans)
    output.append(_line("trishul_analysis_outcome_total", completed, {"outcome": "completed"}))
    output.append(_line("trishul_analysis_outcome_total", failed, {"outcome": "failed"}))
    recovered = Job.all_objects.filter(state=Job.State.COMPLETED, attempts__gt=1).count()
    retried = Job.all_objects.filter(attempts__gt=1).count()
    output.append(_line("trishul_analysis_recovery_total", recovered, {"result": "recovered"}))
    output.append(_line("trishul_analysis_recovery_total", retried, {"result": "retried"}))
    return "".join(output).encode()
