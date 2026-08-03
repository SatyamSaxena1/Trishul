import math
from collections import Counter

from django.db.models import F

from .models import AuditEvent, Finding, FindingReview, Job, RepositoryVersion, Scan

TERMINAL_STATES = (Job.State.COMPLETED, Job.State.FAILED, Job.State.CANCELLED)
SAFE_RESULTS = {"passed", "failed", "partial", "not_run"}
DRILL_ACTIONS = {f"drill.{name}" for name in ("backup", "restore", "installation", "rollback")}
INCIDENT_ACTIONS = {"incident.security", "incident.operational"}


def _percentile(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower), 3)


def _safe_value(value, allowed):
    return value if isinstance(value, str) and value in allowed else "unspecified"


def generate_tenant_report(*, tenant, since, until):
    """Return aggregate-only reporting data for exactly one tenant and time window."""
    jobs = Job.all_objects.filter(tenant=tenant, created_at__gte=since, created_at__lt=until)
    terminal = jobs.filter(state__in=TERMINAL_STATES)
    terminal_count = terminal.count()
    completed_count = terminal.filter(state=Job.State.COMPLETED).count()
    recovered_count = terminal.filter(attempts__gt=1).count()
    durations = [
        value.total_seconds()
        for value in terminal.annotate(duration=F("updated_at") - F("created_at")).values_list("duration", flat=True)
    ]

    versions = RepositoryVersion.all_objects.filter(tenant=tenant, created_at__gte=since, created_at__lt=until)
    successful_versions = (
        Scan.all_objects.filter(
            tenant=tenant,
            repository_version__in=versions,
            state=Scan.State.COMPLETED,
        )
        .values("repository_version_id")
        .distinct()
        .count()
    )
    findings = Finding.all_objects.filter(tenant=tenant, created_at__gte=since, created_at__lt=until)
    finding_counts = dict(sorted(Counter(findings.values_list("rule_id", flat=True)).items()))
    reviews = FindingReview.all_objects.filter(tenant=tenant, created_at__gte=since, created_at__lt=until)
    review_counts = dict(sorted(Counter(reviews.values_list("outcome", flat=True)).items()))
    for outcome, _label in FindingReview.Outcome.choices:
        review_counts.setdefault(outcome, 0)
    reviewed_usefulness = reviews.exclude(useful=None)
    useful_by_rule = {}
    for rule_id in sorted(findings.values_list("rule_id", flat=True).distinct()):
        rule_reviews = reviewed_usefulness.filter(finding__rule_id=rule_id)
        count = rule_reviews.count()
        useful_by_rule[rule_id] = {
            "reviewed": count,
            "useful": rule_reviews.filter(useful=True).count(),
            "rate": round(rule_reviews.filter(useful=True).count() / count, 4) if count else None,
        }
    usefulness_count = reviewed_usefulness.count()

    events = AuditEvent.all_objects.filter(tenant=tenant, occurred_at__gte=since, occurred_at__lt=until)
    incidents = Counter(events.filter(action__in=INCIDENT_ACTIONS).values_list("action", flat=True))
    drills = Counter()
    for action, details in events.filter(action__in=DRILL_ACTIONS).values_list("action", "details"):
        result = _safe_value(details.get("result") if isinstance(details, dict) else None, SAFE_RESULTS)
        drills[(action.removeprefix("drill."), result)] += 1

    failure_causes = Counter(terminal.filter(state=Job.State.FAILED).values_list("error_code", flat=True))
    if "" in failure_causes:
        failure_causes["unspecified"] += failure_causes.pop("")
    total = jobs.count()
    return {
        "scope": {"tenant_id": str(tenant.id), "since": since.isoformat(), "until": until.isoformat()},
        "repositories": {"submitted": versions.count(), "successfully_analyzed": successful_versions},
        "jobs": {
            "total": total,
            "terminal": terminal_count,
            "completion_rate": round(completed_count / total, 4) if total else None,
            "manual_recovery_rate": round(recovered_count / terminal_count, 4) if terminal_count else None,
            "runtime_seconds": {f"p{p}": _percentile(durations, p / 100) for p in (50, 90, 95, 99)},
            "terminal_outcomes": dict(sorted(Counter(terminal.values_list("state", flat=True)).items())),
            "failure_causes": dict(sorted(failure_causes.items())),
        },
        "findings_by_rule": finding_counts,
        "review_outcomes": review_counts,
        "usefulness": {
            "overall": {
                "reviewed": usefulness_count,
                "useful": reviewed_usefulness.filter(useful=True).count(),
                "rate": round(reviewed_usefulness.filter(useful=True).count() / usefulness_count, 4)
                if usefulness_count
                else None,
            },
            "by_rule": useful_by_rule,
        },
        "incidents": {"security": incidents["incident.security"], "operational": incidents["incident.operational"]},
        "drills": {
            name: {result: drills[(name, result)] for result in sorted(SAFE_RESULTS | {"unspecified"})}
            for name in ("backup", "restore", "installation", "rollback")
        },
        "reviewer_feedback": {
            "reviews_with_feedback": reviews.exclude(feedback="").count(),
            "unresolved_blockers": reviews.filter(unresolved_blocker=True).count(),
            "note": "Feedback text is intentionally excluded.",
        },
        "privacy": "Aggregate report; source, evidence, secrets, paths, prompts, and model content are excluded.",
    }
