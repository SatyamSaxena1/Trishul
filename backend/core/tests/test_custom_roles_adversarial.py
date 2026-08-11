"""Adversarial coverage for the custom-role system: escalation attempts,
context-vs-permission separation, tenant isolation, and invalid input."""

from datetime import date

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from core.models import (
    Application,
    Assessment,
    ControlAssignment,
    ControlEvidenceLink,
    CustomRole,
    Evidence,
    FrameworkVersion,
    Membership,
    OrganisationControl,
    Organization,
    Tenant,
    UnifiedControlObjective,
    Workspace,
)
from core.tenancy import tenant_context

pytestmark = pytest.mark.django_db


def member(tenant, username, role):
    user = get_user_model().objects.create(username=username)
    return Membership.all_objects.create(tenant=tenant, user=user, role=role)


def client_for(membership):
    client = APIClient()
    client.force_authenticate(membership.user)
    client.credentials(HTTP_X_TRISHUL_TENANT=str(membership.tenant_id))
    return client


def test_broad_evidence_read_grant_does_not_bypass_control_assignment_scoping():
    """A custom role granting the tenant-wide "evidence.read" permission must not
    let a Control Owner see evidence outside their own ControlAssignment: context
    (assignment) and capability (permission) are independent axes, not one."""
    tenant = Tenant.objects.create(slug="ctx-not-collapsed", name="Context not collapsed")
    admin = member(tenant, "ctx-admin", Membership.Role.ORG_ADMIN)
    owner = member(tenant, "ctx-owner", Membership.Role.CONTROL_OWNER)
    role = client_for(admin).post(
        "/api/v1/custom-roles/", {"name": "Broad evidence reader", "permissions": ["evidence.read"]}, format="json"
    )
    assert role.status_code == 201, role.data
    assert client_for(admin).patch(
        f"/api/v1/memberships/{owner.id}/",
        {"custom_role": role.data["id"]},
        format="json",
        HTTP_IF_MATCH=str(owner.version),
    ).status_code == 200

    with tenant_context(tenant.id):
        org = Organization.objects.create(tenant=tenant, name="Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=org, name="Workspace")
        app = Application.objects.create(tenant=tenant, workspace=workspace, name="App")
        framework = FrameworkVersion.objects.create(
            tenant=tenant,
            framework="Demo",
            version_name="1",
            source_url="https://example.test/demo",
            catalog_hash="e" * 64,
        )
        assessment = Assessment.objects.create(
            tenant=tenant, application=app, framework_version=framework, name="Demo"
        )
        assigned_control = OrganisationControl.objects.create(
            tenant=tenant,
            application=app,
            unified_control=UnifiedControlObjective.objects.create(
                tenant=tenant,
                code="UCO-ASSIGNED",
                domain="access",
                objective="x",
                control_type="preventive",
                nature="process",
            ),
        )
        other_control = OrganisationControl.objects.create(
            tenant=tenant,
            application=app,
            unified_control=UnifiedControlObjective.objects.create(
                tenant=tenant,
                code="UCO-OTHER",
                domain="access",
                objective="y",
                control_type="preventive",
                nature="process",
            ),
        )
        ControlAssignment.objects.create(tenant=tenant, organisation_control=assigned_control, assignee=owner.user)
        other_evidence = Evidence.objects.create(
            tenant=tenant,
            assessment=assessment,
            title="Other control evidence",
            source="manual",
            evidence_date=date.today(),
            object_key=f"{tenant.id}/evidence/other.txt",
            sha256="9" * 64,
            classification="internal",
        )
        other_link = ControlEvidenceLink.objects.create(
            tenant=tenant,
            organisation_control=other_control,
            evidence=other_evidence,
            source_type="manual",
            source_id=other_evidence.id,
            source_hash=other_evidence.sha256,
            verdict="accept",
            reason="Not assigned to this owner.",
            mapping_version="1",
        )

    # The composed permission set genuinely includes evidence.read...
    perms = client_for(admin).get(f"/api/v1/memberships/{owner.id}/effective-permissions/")
    assert "evidence.read" in perms.data["permissions"]
    # ...yet the Evidence queryset is still scoped by role + assignment, not by
    # "does this principal hold a read permission somewhere in their set".
    listed = {item["id"] for item in client_for(owner).get("/api/v1/evidence/").data["results"]}
    assert str(other_evidence.id) not in listed
    assert client_for(owner).get(f"/api/v1/evidence/{other_evidence.id}/").status_code == 404
    links = client_for(owner).get("/api/v1/control-evidence-links/")
    assert links.status_code == 200
    assert str(other_link.id) not in {item["id"] for item in links.data["results"]}
    assert client_for(owner).get(f"/api/v1/control-evidence-links/{other_link.id}/").status_code == 404


def test_custom_role_rejects_nonexistent_permission_codes():
    tenant = Tenant.objects.create(slug="invalid-perm", name="Invalid perm")
    admin = member(tenant, "invalid-admin", Membership.Role.ORG_ADMIN)
    response = client_for(admin).post(
        "/api/v1/custom-roles/", {"name": "Fake", "permissions": ["totally.fake.permission"]}, format="json"
    )
    assert response.status_code == 403
    assert not CustomRole.objects.filter(name="Fake").exists()


def test_custom_role_deduplicates_repeated_permission_grants():
    tenant = Tenant.objects.create(slug="dup-perm", name="Dup perm")
    admin = member(tenant, "dup-admin", Membership.Role.ORG_ADMIN)
    response = client_for(admin).post(
        "/api/v1/custom-roles/",
        {"name": "Dup", "permissions": ["control.read", "control.read", "control.read"]},
        format="json",
    )
    assert response.status_code == 201, response.data
    assert response.data["permissions"] == ["control.read"]


def test_inactive_membership_cannot_authenticate_into_the_tenant():
    tenant = Tenant.objects.create(slug="inactive-member", name="Inactive member")
    membership = member(tenant, "inactive-user", Membership.Role.ORG_ADMIN)
    membership.is_active = False
    membership.save(update_fields=["is_active"])
    assert client_for(membership).get("/api/v1/applications/").status_code == 403


def test_deleted_custom_role_reference_cannot_grant_access():
    """A retired (soft-deleted-equivalent) custom role stops granting its permissions
    the moment it's inactive, even though the membership's FK still points at it."""
    tenant = Tenant.objects.create(slug="retired-role", name="Retired role")
    admin = member(tenant, "retire-admin", Membership.Role.ORG_ADMIN)
    owner = member(tenant, "retire-owner", Membership.Role.CONTROL_OWNER)
    role = client_for(admin).post(
        "/api/v1/custom-roles/", {"name": "Temp", "permissions": ["control.read"]}, format="json"
    ).data
    client_for(admin).patch(
        f"/api/v1/memberships/{owner.id}/",
        {"custom_role": role["id"]},
        format="json",
        HTTP_IF_MATCH=str(owner.version),
    )
    assert client_for(admin).post(f"/api/v1/custom-roles/{role['id']}/retire/").status_code == 204
    perms = client_for(admin).get(f"/api/v1/memberships/{owner.id}/effective-permissions/")
    assert "control.read" not in perms.data["permissions"]


def test_only_a_role_editor_permission_holder_can_manage_custom_roles():
    tenant = Tenant.objects.create(slug="role-mgmt", name="Role mgmt")
    owner = member(tenant, "unauthorized-owner", Membership.Role.CONTROL_OWNER)
    assert client_for(owner).post(
        "/api/v1/custom-roles/", {"name": "Should fail", "permissions": ["control.read"]}, format="json"
    ).status_code == 403


def test_tenant_b_cannot_assign_tenant_as_custom_role():
    tenant_a = Tenant.objects.create(slug="cross-a", name="Cross A")
    tenant_b = Tenant.objects.create(slug="cross-b", name="Cross B")
    admin_a = member(tenant_a, "cross-admin-a", Membership.Role.ORG_ADMIN)
    admin_b = member(tenant_b, "cross-admin-b", Membership.Role.ORG_ADMIN)
    owner_b = member(tenant_b, "cross-owner-b", Membership.Role.CONTROL_OWNER)

    role_a = client_for(admin_a).post(
        "/api/v1/custom-roles/", {"name": "Tenant A role", "permissions": ["control.read"]}, format="json"
    ).data

    # Tenant B cannot even see Tenant A's role (tenant-scoped queryset)...
    assert client_for(admin_b).get(f"/api/v1/custom-roles/{role_a['id']}/").status_code == 404
    # ...and cannot assign its id to a Tenant B membership either.
    response = client_for(admin_b).patch(
        f"/api/v1/memberships/{owner_b.id}/",
        {"custom_role": role_a["id"]},
        format="json",
        HTTP_IF_MATCH=str(owner_b.version),
    )
    assert response.status_code in (400, 403, 404)
    owner_b.refresh_from_db()
    assert owner_b.custom_role_id is None
