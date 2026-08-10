from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import Membership, ScimIdentity, Tenant, TenantInvitation

pytestmark = pytest.mark.django_db


def member(tenant, username, role=Membership.Role.ORG_ADMIN, email=""):
    user = get_user_model().objects.create(username=username, email=email or f"{username}@example.test")
    Membership.all_objects.create(tenant=tenant, user=user, role=role)
    return user


def tenant_client(tenant, user):
    client = APIClient()
    client.force_authenticate(user)
    client.credentials(HTTP_X_TRISHUL_TENANT=str(tenant.id))
    return client


def test_invitation_is_hashed_single_use_and_email_bound():
    tenant = Tenant.objects.create(slug="invite", name="Invite")
    admin = member(tenant, "invite-admin")
    invited = get_user_model().objects.create(username="invitee", email="invitee@example.test")
    response = tenant_client(tenant, admin).post(
        "/api/v1/tenant-invitations/",
        {
            "email": invited.email,
            "role": Membership.Role.CONTROL_OWNER,
            "expires_at": (timezone.now() + timedelta(days=1)).isoformat(),
        },
        format="json",
    )
    assert response.status_code == 201, response.data
    token = response.data["token"]
    invitation = TenantInvitation.all_objects.get(pk=response.data["id"])
    assert token not in invitation.token_hash

    client = APIClient()
    client.force_authenticate(invited)
    accepted = client.post(f"/api/v1/invitations/{token}/accept")
    assert accepted.status_code == 200, accepted.data
    assert Membership.all_objects.get(tenant=tenant, user=invited).role == Membership.Role.CONTROL_OWNER
    assert client.post(f"/api/v1/invitations/{token}/accept").status_code == 400


def test_invitation_rejects_the_wrong_authenticated_email():
    tenant = Tenant.objects.create(slug="invite-email", name="Invite email")
    admin = member(tenant, "email-admin")
    wrong = get_user_model().objects.create(username="wrong", email="wrong@example.test")
    response = tenant_client(tenant, admin).post(
        "/api/v1/tenant-invitations/",
        {
            "email": "right@example.test",
            "role": Membership.Role.CONTROL_OWNER,
            "expires_at": (timezone.now() + timedelta(days=1)).isoformat(),
        },
        format="json",
    )
    client = APIClient()
    client.force_authenticate(wrong)
    assert client.post(f"/api/v1/invitations/{response.data['token']}/accept").status_code == 403
    assert not Membership.all_objects.filter(tenant=tenant, user=wrong).exists()


def test_scim_provisions_and_deactivates_only_the_target_tenant_membership():
    tenant = Tenant.objects.create(slug="scim-a", name="SCIM A")
    other = Tenant.objects.create(slug="scim-b", name="SCIM B")
    admin = member(tenant, "scim-admin")
    credential = tenant_client(tenant, admin).post(
        "/api/v1/scim-credentials/",
        {"name": "Entra", "default_role": Membership.Role.CONTROL_OWNER},
        format="json",
    )
    assert credential.status_code == 201, credential.data
    headers = {"HTTP_AUTHORIZATION": f"Bearer {credential.data['token']}"}
    provisioned = APIClient().post(
        "/api/v1/scim/v2/scim-a/Users",
        {"userName": "owner@example.test", "externalId": "entra-123", "active": True},
        format="json",
        **headers,
    )
    assert provisioned.status_code == 201, provisioned.data
    identity = ScimIdentity.all_objects.get(pk=provisioned.data["id"])
    Membership.all_objects.create(tenant=other, user=identity.user, role=Membership.Role.RISK_OWNER)

    patched = APIClient().patch(
        f"/api/v1/scim/v2/scim-a/Users/{identity.id}",
        {"Operations": [{"op": "Replace", "path": "active", "value": False}]},
        format="json",
        **headers,
    )
    assert patched.status_code == 200, patched.data
    assert not Membership.all_objects.get(tenant=tenant, user=identity.user).is_active
    assert Membership.all_objects.get(tenant=other, user=identity.user).is_active
    assert identity.user.is_active


def test_scim_token_cannot_cross_tenants():
    tenant = Tenant.objects.create(slug="scim-source", name="SCIM source")
    Tenant.objects.create(slug="scim-target", name="SCIM target")
    admin = member(tenant, "scim-cross-admin")
    credential = tenant_client(tenant, admin).post(
        "/api/v1/scim-credentials/",
        {"name": "Provisioner", "default_role": Membership.Role.CONTROL_OWNER},
        format="json",
    )
    response = APIClient().get(
        "/api/v1/scim/v2/scim-target/Users",
        HTTP_AUTHORIZATION=f"Bearer {credential.data['token']}",
    )
    assert response.status_code == 403


def test_scim_credential_cannot_grant_a_role_from_another_tenant_type():
    tenant = Tenant.objects.create(slug="scim-role", name="SCIM role")
    admin = member(tenant, "scim-role-admin")
    response = tenant_client(tenant, admin).post(
        "/api/v1/scim-credentials/",
        {"name": "Unsafe", "default_role": Membership.Role.PLATFORM_ADMIN},
        format="json",
    )
    assert response.status_code == 400
