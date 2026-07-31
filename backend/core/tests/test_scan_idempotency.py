from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from time import sleep
from unittest.mock import patch

import pytest
from django.db import OperationalError, close_old_connections
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import (
    Application,
    Job,
    Organization,
    Repository,
    RepositoryVersion,
    Scan,
    ServiceAccount,
    Tenant,
    Workspace,
)
from core.tenancy import tenant_context


def scan_fixture():
    tenant = Tenant.objects.create(slug="scan-tenant", name="Scan Tenant")
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name="Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name="Workspace")
        application = Application.objects.create(tenant=tenant, workspace=workspace, name="App")
        repository = Repository.objects.create(tenant=tenant, application=application, name="Repo")
        version = RepositoryVersion.objects.create(
            tenant=tenant,
            repository=repository,
            object_key="repositories/archive.tar",
            sha256="a" * 64,
            size=100,
            manifest={"files": []},
        )
    _, token = ServiceAccount.issue(
        tenant=tenant,
        name="scanner",
        scopes=["scan.create"],
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return tenant, version, token


def payload(version):
    return {
        "repository_version": str(version.id),
        "language_pack": "python-stdlib",
        "language_pack_version": "1.0",
        "configuration": {"minimum_confidence": 3},
        "enabled_rules": ["PY-002", "PY-001"],
    }


@pytest.mark.django_db(transaction=True)
def test_repeated_equivalent_scan_returns_existing_job():
    tenant, version, token = scan_fixture()
    client = APIClient()
    headers = {"HTTP_AUTHORIZATION": f"Bearer {token}", "HTTP_IDEMPOTENCY_KEY": "build-42"}
    with patch("core.tasks.publish_scan", return_value=True):
        first = client.post("/api/v1/scans/", payload(version), format="json", **headers)
        second = client.post("/api/v1/scans/", payload(version), format="json", **headers)

    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["deduplicated"] is True
    assert first.json()["job"]["id"] == second.json()["job"]["id"]
    assert Job.all_objects.filter(tenant=tenant).count() == 1
    assert Scan.all_objects.filter(tenant=tenant).count() == 1


@pytest.mark.django_db(transaction=True)
def test_simultaneous_equivalent_submissions_create_one_logical_job():
    tenant, version, token = scan_fixture()
    barrier = Barrier(2)

    def submit():
        close_old_connections()
        client = APIClient()
        barrier.wait()
        for attempt in range(5):
            try:
                response = client.post(
                    "/api/v1/scans/",
                    payload(version),
                    format="json",
                    HTTP_AUTHORIZATION=f"Bearer {token}",
                    HTTP_IDEMPOTENCY_KEY="concurrent-build",
                )
                break
            except OperationalError:
                # SQLite locks the entire table; PostgreSQL instead reaches the
                # unique-index race directly. Retrying models the client retry.
                close_old_connections()
                sleep(0.05 * (attempt + 1))
        else:
            raise AssertionError("submission remained database-locked")
        close_old_connections()
        return response

    with patch("core.tasks.publish_scan", return_value=True), ThreadPoolExecutor(max_workers=2) as executor:
        responses = [future.result() for future in [executor.submit(submit), executor.submit(submit)]]

    assert all(response.status_code in {200, 201} for response in responses)
    assert len({response.json()["job"]["id"] for response in responses}) == 1
    assert Job.all_objects.filter(tenant=tenant).count() == 1
    assert Scan.all_objects.filter(tenant=tenant).count() == 1


@pytest.mark.django_db(transaction=True)
def test_publication_failure_keeps_durable_dispatch_intent():
    tenant, version, token = scan_fixture()
    client = APIClient()
    with patch("core.tasks.execute_scan.apply_async", side_effect=ConnectionError("broker unavailable")):
        response = client.post(
            "/api/v1/scans/",
            payload(version),
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    assert response.status_code == 201
    job = Job.all_objects.get(tenant=tenant)
    assert job.dispatch_pending is True
    assert job.state == Job.State.QUEUED
    assert job.error_code == "queue_publish_failed"
