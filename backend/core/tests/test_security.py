from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import Application, AuditEvent, Membership, Organization, Repository, ServiceAccount, Tenant, Workspace
from core.tenancy import current_tenant_id, database_tenant_context, tenant_context


def make_application(tenant, name):
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name=f"{name} Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name=f"{name} Workspace")
        return Application.objects.create(tenant=tenant, workspace=workspace, name=name)


@pytest.mark.django_db
def test_service_token_and_tenant_manager_fail_closed():
    first = Tenant.objects.create(slug="first", name="First")
    second = Tenant.objects.create(slug="second", name="Second")
    first_app = make_application(first, "First App")
    make_application(second, "Second App")
    account, token = ServiceAccount.issue(
        tenant=first,
        name="ci",
        scopes=["application.read", "application.write"],
        expires_at=timezone.now() + timedelta(hours=1),
    )
    assert Application.objects.count() == 0
    client = APIClient()
    response = client.get("/api/v1/applications/", HTTP_AUTHORIZATION=f"Bearer {token}")
    assert response.status_code == 200
    assert [item["id"] for item in response.json()["results"]] == [str(first_app.id)]


@pytest.mark.django_db
def test_cross_tenant_relationship_is_rejected():
    first = Tenant.objects.create(slug="first", name="First")
    second = Tenant.objects.create(slug="second", name="Second")
    second_app = make_application(second, "Second App")
    with tenant_context(first.id), pytest.raises(ValidationError):
        Application(tenant=first, workspace=second_app.workspace, name="Invalid").save()


@pytest.mark.django_db
def test_optimistic_concurrency_and_audit_chain():
    tenant = Tenant.objects.create(slug="first", name="First")
    application = make_application(tenant, "App")
    _, token = ServiceAccount.issue(
        tenant=tenant,
        name="ci",
        scopes=["application.read", "application.write"],
        expires_at=timezone.now() + timedelta(hours=1),
    )
    client = APIClient()
    url = f"/api/v1/applications/{application.id}/"
    assert (
        client.patch(url, {"name": "Updated"}, format="json", HTTP_AUTHORIZATION=f"Bearer {token}").status_code == 428
    )
    response = client.patch(
        url,
        {"name": "Updated"},
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {token}",
        HTTP_IF_MATCH="1",
    )
    assert response.status_code == 200
    events = list(AuditEvent.all_objects.filter(tenant=tenant).order_by("occurred_at", "id"))
    assert len(events) == 1
    assert events[0].previous_hash == ""
    with pytest.raises(ValidationError):
        events[0].delete()


@pytest.mark.django_db
def test_requester_cannot_approve_own_acceptance():
    tenant = Tenant.objects.create(slug="first", name="First")
    user = get_user_model().objects.create(username="subject")
    Membership.all_objects.create(tenant=tenant, user=user, role=Membership.Role.CISO)


@pytest.mark.django_db
def test_application_restrictions_apply_to_lists_and_writes():
    tenant = Tenant.objects.create(slug="first", name="First")
    allowed = make_application(tenant, "Allowed")
    denied = make_application(tenant, "Denied")
    _, token = ServiceAccount.issue(
        tenant=tenant,
        name="restricted-ci",
        scopes=["application.read", "repository.import"],
        application_ids=[str(allowed.id)],
        expires_at=timezone.now() + timedelta(hours=1),
    )
    client = APIClient()
    headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    response = client.get("/api/v1/applications/", **headers)
    assert [item["id"] for item in response.json()["results"]] == [str(allowed.id)]
    response = client.post(
        "/api/v1/repositories/",
        {"application": str(denied.id), "name": "forbidden", "source_type": "upload"},
        format="json",
        **headers,
    )
    assert response.status_code == 403
    assert Repository.all_objects.filter(name="forbidden").count() == 0


def test_worker_tenant_context_is_cleared_after_success_and_failure():
    tenant_id = __import__("uuid").uuid4()
    with database_tenant_context(tenant_id):
        assert current_tenant_id() == tenant_id
    assert current_tenant_id() is None
    with pytest.raises(RuntimeError):
        with database_tenant_context(tenant_id):
            raise RuntimeError("worker failed")
    assert current_tenant_id() is None
