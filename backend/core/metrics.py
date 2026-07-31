import os
import shutil
from pathlib import Path

import redis
from django.conf import settings
from django.utils import timezone
from prometheus_client.core import GaugeMetricFamily, HistogramMetricFamily

from .models import AIAnalysisRun, Job, Tenant
from .storage import healthcheck as storage_healthcheck
from .tenancy import tenant_context

DURATION_BUCKETS = (30, 60, 120, 300, 600, 900, 1800, 3600)


def _histogram(name, documentation, observations):
    metric = HistogramMetricFamily(name, documentation)
    cumulative = [(str(limit), sum(value <= limit for value in observations)) for limit in DURATION_BUCKETS]
    cumulative.append(("+Inf", len(observations)))
    metric.add_metric([], cumulative, sum(observations))
    return metric


def _backup_state():
    root = Path(os.getenv("BACKUP_DIR", "/var/lib/trishul/backups"))
    candidates = sorted((item for item in root.glob("*") if item.is_dir()), reverse=True) if root.exists() else []
    if not candidates:
        return float("inf"), 0
    latest = candidates[0]
    age = max(0, timezone.now().timestamp() - latest.stat().st_mtime)
    try:
        verified = 1 if (latest / "verification.status").read_text().strip() == "success" else 0
    except OSError:
        verified = 0
    return age, verified


class TrishulCollector:
    """Collect only deployment-wide, bounded-label operational data."""

    def collect(self):
        state_counts = {state: 0 for state, _ in Job.State.choices}
        retries = recoveries = stale = 0
        waits, durations = [], []
        analyzer_failures = {"failure": 0, "timeout": 0}
        ai_failures = 0
        now = timezone.now()
        for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True).iterator():
            with tenant_context(tenant_id):
                jobs = list(
                    Job.objects.only(
                        "state", "attempts", "recovery_count", "created_at", "started_at", "finished_at",
                        "lease_expires_at", "error_code"
                    )
                )
                for job in jobs:
                    state_counts[job.state] += 1
                    retries += max(0, job.attempts - 1)
                    recoveries += job.recovery_count
                    stale += int(job.state == Job.State.RUNNING and job.lease_expires_at and job.lease_expires_at < now)
                    if job.started_at:
                        waits.append((job.started_at - job.created_at).total_seconds())
                    if job.started_at and job.finished_at:
                        durations.append((job.finished_at - job.started_at).total_seconds())
                    if job.state == Job.State.FAILED:
                        outcome = "timeout" if "timeout" in job.error_code.lower() else "failure"
                        analyzer_failures[outcome] += 1
                ai_failures += AIAnalysisRun.objects.filter(state="failed").count()

        submitted = GaugeMetricFamily("trishul_jobs_submitted_total", "Jobs submitted since records began")
        submitted.add_metric([], sum(state_counts.values()))
        yield submitted
        terminal = GaugeMetricFamily(
            "trishul_jobs_terminal_total", "Terminal jobs by bounded outcome", labels=["outcome"]
        )
        for outcome in (Job.State.COMPLETED, Job.State.FAILED, Job.State.CANCELLED):
            terminal.add_metric([outcome], state_counts[outcome])
        yield terminal
        active = GaugeMetricFamily("trishul_jobs_active", "Jobs currently executing")
        active.add_metric([], state_counts[Job.State.RUNNING])
        yield active
        stale_metric = GaugeMetricFamily("trishul_jobs_stale", "Running jobs with expired leases")
        stale_metric.add_metric([], stale)
        yield stale_metric
        retry_metric = GaugeMetricFamily("trishul_job_retries_total", "Job attempts after the first attempt")
        retry_metric.add_metric([], retries)
        yield retry_metric
        recovery_metric = GaugeMetricFamily("trishul_job_recoveries_total", "Expired leases reconciled")
        recovery_metric.add_metric([], recoveries)
        yield recovery_metric
        yield _histogram("trishul_job_duration_seconds", "Terminal job execution duration", durations)
        yield _histogram("trishul_job_queue_wait_seconds", "Time from submission to execution", waits)

        queue = GaugeMetricFamily("trishul_queue_depth", "Broker messages waiting by bounded queue", labels=["queue"])
        try:
            client = redis.from_url(settings.CELERY_BROKER_URL, socket_timeout=2)
            for name in ("default", "analysis"):
                queue.add_metric([name], client.llen(name))
        except Exception:
            for name in ("default", "analysis"):
                queue.add_metric([name], -1)
        yield queue
        analyzer = GaugeMetricFamily(
            "trishul_analyzer_failures_total", "Deterministic analyzer failures by bounded reason", labels=["reason"]
        )
        for reason, count in analyzer_failures.items():
            analyzer.add_metric([reason], count)
        yield analyzer
        ai = GaugeMetricFamily("trishul_ai_failures_total", "AI gateway failures recorded since records began")
        ai.add_metric([], ai_failures)
        yield ai

        disk = GaugeMetricFamily(
            "trishul_host_disk_available_bytes", "Available capacity on the application host volume"
        )
        disk.add_metric([], shutil.disk_usage(os.getenv("HOST_CAPACITY_PATH", os.getcwd())).free)
        yield disk
        backup_age, backup_verified = _backup_state()
        backup = GaugeMetricFamily("trishul_backup_age_seconds", "Age of the latest local database backup")
        backup.add_metric([], backup_age)
        yield backup
        verification = GaugeMetricFamily(
            "trishul_backup_last_verification_success", "Whether the latest backup verified (1/0)"
        )
        verification.add_metric([], backup_verified)
        yield verification
        storage = GaugeMetricFamily(
            "trishul_object_store_ready", "Whether object storage is configured and reachable (1/0)"
        )
        try:
            if not settings.S3_ENDPOINT_URL:
                raise RuntimeError("unconfigured")
            storage_healthcheck()
            ready = 1
        except Exception:
            ready = 0
        storage.add_metric([], ready)
        yield storage
