import os
import subprocess
import sys

import pytest
from django.conf import settings
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APIClient

from core.models import Engagement, Tenant
from core.tenancy import tenant_context

pytestmark = pytest.mark.django_db


def test_dev_auth_is_disabled_by_default():
    assert settings.TRISHUL_DEV_AUTH is False


def test_dev_auth_cannot_start_without_debug():
    environment = os.environ.copy()
    environment.update({"DEBUG": "false", "TRISHUL_DEV_AUTH": "true", "DJANGO_SECRET_KEY": "test-secret"})
    result = subprocess.run(  # noqa: S603 - fixed interpreter and code, isolated test environment
        [sys.executable, "-c", "import trishul.settings"],
        cwd=settings.BASE_DIR,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "TRISHUL_DEV_AUTH is strictly local" in result.stderr


@pytest.fixture
def dev_data():
    with override_settings(DEBUG=True, TRISHUL_DEV_AUTH=True):
        call_command("seed_dev", verbosity=0)
        yield


def dev_client(username, tenant):
    client = APIClient()
    client.credentials(HTTP_X_TRISHUL_DEV_USER=username, HTTP_X_TRISHUL_TENANT=str(tenant.id))
    return client


def test_dev_identity_still_denies_cross_tenant_membership(dev_data):
    auditee = Tenant.objects.get(slug="dev-auditee")
    firm = Tenant.objects.get(slug="dev-firm")
    assert dev_client("dev-org-admin", auditee).get("/api/v1/context").status_code == 200
    assert dev_client("dev-org-admin", firm).get("/api/v1/context").status_code == 403


def test_dev_persona_permissions_and_control_assignments_are_enforced(dev_data):
    auditee = Tenant.objects.get(slug="dev-auditee")
    assert dev_client("dev-risk-owner", auditee).get("/api/v1/applications/").status_code == 403
    controls = dev_client("dev-control-owner", auditee).get("/api/v1/organisation-controls/")
    assert controls.status_code == 200
    assert len(controls.json()["results"]) == 1


def test_dev_identity_does_not_bypass_workflow_guards(dev_data):
    firm = Tenant.objects.get(slug="dev-firm")
    engagement = Engagement.all_objects.get(tenant=firm, reference="DEV-ENG-001")
    response = dev_client("dev-audit-manager", firm).post(
        f"/api/v1/engagements/{engagement.id}/transition/",
        {"event": "close"},
        format="json",
        HTTP_IF_MATCH=str(engagement.version),
    )
    assert response.status_code == 400
    engagement.refresh_from_db()
    assert engagement.status == Engagement.Status.ACTIVE


def test_dev_auditor_engagement_restrictions_are_enforced(dev_data):
    firm = Tenant.objects.get(slug="dev-firm")
    engagement = Engagement.all_objects.get(tenant=firm, reference="DEV-ENG-001")
    client = dev_client("dev-auditor", firm)
    url = f"/api/v1/engagements/{engagement.id}/assurance-results/"
    assert client.get(url).status_code == 200
    with tenant_context(firm.id):
        Engagement.all_objects.filter(pk=engagement.id).update(status=Engagement.Status.REVOKED)
    assert client.get(url).status_code == 403
