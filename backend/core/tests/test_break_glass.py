from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import BreakGlassGrant, Membership, Organization, Tenant, TenantNotification

pytestmark = pytest.mark.django_db


def add_member(tenant, username, role):
    user = get_user_model().objects.create(username=username, email=f"{username}@example.test")
    Membership.all_objects.create(tenant=tenant, user=user, role=role)
    return user


def client_for(user, tenant, grant=None):
    client = APIClient()
    client.force_authenticate(user)
    headers = {"HTTP_X_TRISHUL_TENANT": str(tenant.id)}
    if grant:
        headers["HTTP_X_TRISHUL_BREAK_GLASS"] = str(grant.id)
    client.credentials(**headers)
    return client


def test_break_glass_is_approved_scoped_audited_and_immediately_revocable():
    platform = Tenant.objects.create(slug="platform-bg", name="Platform", tenant_type=Tenant.Type.PLATFORM)
    target = Tenant.objects.create(slug="target-bg", name="Target")
    other = Tenant.objects.create(slug="other-bg", name="Other")
    support = add_member(platform, "support", Membership.Role.PLATFORM_ADMIN)
    admin = add_member(target, "target-admin", Membership.Role.ORG_ADMIN)
    Organization.all_objects.create(tenant=target, name="Visible only by grant")

    assert client_for(support, target).get("/api/v1/organizations/").status_code == 403
    requested = client_for(support, platform).post(
        "/api/v1/tenant-admin/break-glass/",
        {
            "target_tenant": str(target.id),
            "reason": "Investigate customer incident INC-42",
            "scopes": ["application.read"],
            "expires_at": (timezone.now() + timedelta(hours=1)).isoformat(),
        },
        format="json",
    )
    assert requested.status_code == 201, requested.data
    grant = BreakGlassGrant.all_objects.get(pk=requested.data["id"])
    approved = client_for(admin, target).post(f"/api/v1/break-glass-grants/{grant.id}/approve/")
    assert approved.status_code == 200, approved.data
    assert TenantNotification.all_objects.filter(tenant=target, kind="break_glass.approved").exists()

    allowed = client_for(support, target, grant).get("/api/v1/organizations/")
    assert allowed.status_code == 200, allowed.data
    assert client_for(support, other, grant).get("/api/v1/organizations/").status_code == 403
    assert client_for(support, target, grant).post("/api/v1/organizations/", {"name": "Denied"}).status_code == 403

    assert client_for(admin, target).post(f"/api/v1/break-glass-grants/{grant.id}/revoke/").status_code == 204
    assert client_for(support, target, grant).get("/api/v1/organizations/").status_code == 403


def test_break_glass_rejects_missing_reason_and_excessive_scope():
    platform = Tenant.objects.create(slug="platform-bg-invalid", name="Platform", tenant_type=Tenant.Type.PLATFORM)
    target = Tenant.objects.create(slug="target-bg-invalid", name="Target")
    support = add_member(platform, "support-invalid", Membership.Role.PLATFORM_ADMIN)
    base = {"target_tenant": str(target.id), "expires_at": (timezone.now() + timedelta(hours=1)).isoformat()}
    assert client_for(support, platform).post(
        "/api/v1/tenant-admin/break-glass/", {**base, "reason": "", "scopes": ["application.read"]}, format="json"
    ).status_code == 400
    assert client_for(support, platform).post(
        "/api/v1/tenant-admin/break-glass/",
        {**base, "reason": "Escalate", "scopes": ["platform.manage"]},
        format="json",
    ).status_code == 400
