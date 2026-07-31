from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.utils import timezone

from core.models import AuditEvent, Job, Tenant
from core.tasks import MAX_ATTEMPTS, reconcile_jobs
from core.tenancy import tenant_context


def stale_job(tenant, *, attempts=1):
    scan_id = uuid4()
    with tenant_context(tenant.id):
        return Job.objects.create(
            tenant=tenant,
            kind="scan",
            payload={"scan_id": str(scan_id)},
            state=Job.State.RUNNING,
            attempts=attempts,
            lease_expires_at=timezone.now() - timedelta(minutes=1),
        )


@pytest.mark.django_db
def test_reconciliation_defers_when_analyzer_may_be_active():
    tenant = Tenant.objects.create(slug="tenant", name="Tenant")
    job = stale_job(tenant)
    with patch("core.tasks.analyzer_status", return_value="unknown"), patch(
        "core.tasks.cleanup_resources"
    ) as cleanup, patch("core.tasks.execute_scan.apply_async") as dispatch:
        reconcile_jobs()
    job.refresh_from_db()
    assert job.state == Job.State.RUNNING
    assert job.error_code == "runtime_unreachable"
    assert job.lease_expires_at > timezone.now()
    cleanup.assert_not_called()
    dispatch.assert_not_called()
    assert AuditEvent.all_objects.filter(resource_id=str(job.id), action="job.recovery_deferred").exists()


@pytest.mark.django_db
def test_reconciliation_cleans_then_reclaims_confirmed_inactive_job():
    tenant = Tenant.objects.create(slug="tenant", name="Tenant")
    job = stale_job(tenant)
    with patch("core.tasks.analyzer_status", return_value="inactive"), patch(
        "core.tasks.cleanup_resources"
    ) as cleanup, patch("core.tasks.execute_scan.apply_async") as dispatch:
        reconcile_jobs()
    job.refresh_from_db()
    assert job.state == Job.State.QUEUED
    assert job.lease_expires_at is None
    cleanup.assert_called_once_with(job.payload["scan_id"])
    dispatch.assert_called_once()
    assert AuditEvent.all_objects.filter(resource_id=str(job.id), action="job.reclaimed").exists()


@pytest.mark.django_db
def test_reconciliation_exhaustion_is_infrastructure_failure():
    tenant = Tenant.objects.create(slug="tenant", name="Tenant")
    job = stale_job(tenant, attempts=MAX_ATTEMPTS)
    with patch("core.tasks.analyzer_status", return_value="inactive"), patch(
        "core.tasks.cleanup_resources"
    ), patch("core.tasks.execute_scan.apply_async") as dispatch:
        reconcile_jobs()
    job.refresh_from_db()
    assert job.state == Job.State.FAILED
    assert job.error_code == "infrastructure_failure"
    dispatch.assert_not_called()
    assert AuditEvent.all_objects.filter(resource_id=str(job.id), action="job.infrastructure_failed").exists()
