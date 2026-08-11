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


def test_custom_role_is_delegated_tenant_scoped_and_rechecked_each_request():
    tenant = Tenant.objects.create(slug="roles", name="Roles")
    other = Tenant.objects.create(slug="roles-other", name="Roles other")
    admin = member(tenant, "role-admin", Membership.Role.ORG_ADMIN)
    owner = member(tenant, "role-owner", Membership.Role.CONTROL_OWNER)
    role_response = client_for(admin).post(
        "/api/v1/custom-roles/", {"name": "Control reader", "permissions": ["control.read"]}, format="json"
    )
    assert role_response.status_code == 201, role_response.data
    role = CustomRole.all_objects.get(pk=role_response.data["id"])
    assigned = client_for(admin).patch(
        f"/api/v1/memberships/{owner.id}/",
        {"custom_role": str(role.id)},
        format="json",
        HTTP_IF_MATCH=str(owner.version),
    )
    assert assigned.status_code == 200, assigned.data

    with tenant_context(tenant.id):
        org = Organization.objects.create(tenant=tenant, name="Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=org, name="Workspace")
        app = Application.objects.create(tenant=tenant, workspace=workspace, name="App")
        controls = []
        for code in ("UCO-1", "UCO-2"):
            uco = UnifiedControlObjective.objects.create(
                tenant=tenant,
                code=code,
                domain="access",
                objective=code,
                control_type="preventive",
                nature="process",
            )
            controls.append(OrganisationControl.objects.create(tenant=tenant, application=app, unified_control=uco))
        ControlAssignment.objects.create(tenant=tenant, organisation_control=controls[0], assignee=owner.user)

    response = client_for(owner).get("/api/v1/organisation-controls/")
    assert response.status_code == 200
    assert [item["id"] for item in response.data["results"]] == [str(controls[0].id)]
    cross_tenant = APIClient()
    cross_tenant.force_authenticate(owner.user)
    assert cross_tenant.get(
        "/api/v1/organisation-controls/", HTTP_X_TRISHUL_TENANT=str(other.id)
    ).status_code == 403

    assert client_for(admin).post(f"/api/v1/custom-roles/{role.id}/retire/").status_code == 204
    # Retiring the delegated role must be rechecked live, not cached: the
    # composed permission set immediately drops what only the custom role
    # granted, while the control owner's own built-in, assignment-scoped
    # "control.assigned" grant is untouched -- retiring one role must not
    # silently revoke access the role never granted in the first place.
    after_retire = client_for(admin).get(f"/api/v1/memberships/{owner.id}/effective-permissions/")
    assert after_retire.status_code == 200
    assert "control.read" not in after_retire.data["permissions"]
    assert "control.assigned" in after_retire.data["permissions"]
    assert client_for(owner).get("/api/v1/organisation-controls/").status_code == 200


def test_custom_roles_deny_platform_permissions_and_self_escalation():
    tenant = Tenant.objects.create(slug="role-denials", name="Role denials")
    admin = member(tenant, "denial-admin", Membership.Role.ORG_ADMIN)
    compliance = member(tenant, "denial-compliance", Membership.Role.COMPLIANCE_MANAGER)
    assert client_for(admin).post(
        "/api/v1/custom-roles/", {"name": "Platform", "permissions": ["platform.manage"]}, format="json"
    ).status_code == 403
    assert client_for(compliance).post(
        "/api/v1/custom-roles/", {"name": "Escalate", "permissions": ["membership.manage"]}, format="json"
    ).status_code == 403
    assert client_for(admin).patch(
        f"/api/v1/memberships/{admin.id}/",
        {"role": Membership.Role.CISO},
        format="json",
        HTTP_IF_MATCH=str(admin.version),
    ).status_code == 403


def test_control_owner_cannot_read_evidence_scoped_to_a_different_control():
    tenant = Tenant.objects.create(slug="evidence-scope", name="Evidence scope")
    owner = member(tenant, "scoped-owner", Membership.Role.CONTROL_OWNER)
    with tenant_context(tenant.id):
        org = Organization.objects.create(tenant=tenant, name="Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=org, name="Workspace")
        app = Application.objects.create(tenant=tenant, workspace=workspace, name="App")
        framework = FrameworkVersion.objects.create(
            tenant=tenant,
            framework="Demo",
            version_name="1",
            source_url="https://example.test/demo",
            catalog_hash="c" * 64,
        )
        assessment = Assessment.objects.create(tenant=tenant, application=app, framework_version=framework, name="Demo")
        control_a, control_b = (
            OrganisationControl.objects.create(
                tenant=tenant,
                application=app,
                unified_control=UnifiedControlObjective.objects.create(
                    tenant=tenant,
                    code=code,
                    domain="access",
                    objective=code,
                    control_type="preventive",
                    nature="process",
                ),
            )
            for code in ("UCO-A", "UCO-B")
        )
        ControlAssignment.objects.create(tenant=tenant, organisation_control=control_a, assignee=owner.user)

        evidence_a = Evidence.objects.create(
            tenant=tenant,
            assessment=assessment,
            title="Control A evidence",
            source="manual",
            evidence_date=date.today(),
            object_key=f"{tenant.id}/evidence/a.txt",
            sha256="a" * 64,
            classification="internal",
        )
        evidence_b = Evidence.objects.create(
            tenant=tenant,
            assessment=assessment,
            title="Control B evidence",
            source="manual",
            evidence_date=date.today(),
            object_key=f"{tenant.id}/evidence/b.txt",
            sha256="b" * 64,
            classification="internal",
        )
        for control, evidence in ((control_a, evidence_a), (control_b, evidence_b)):
            ControlEvidenceLink.objects.create(
                tenant=tenant,
                organisation_control=control,
                evidence=evidence,
                source_type="manual",
                source_id=evidence.id,
                source_hash=evidence.sha256,
                verdict="accept",
                reason="Manual test link.",
                mapping_version="1",
            )

    client = client_for(owner)
    listed = client.get("/api/v1/evidence/")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.data["results"]] == [str(evidence_a.id)]

    # Alice can reach evidence linked to her own assigned control...
    assert client.get(f"/api/v1/evidence/{evidence_a.id}/").status_code == 200

    # ...but every write path to Evidence B is denied by direct-ID access too --
    # sharing an application does not imply sharing control-scoped evidence.
    assert client.get(f"/api/v1/evidence/{evidence_b.id}/").status_code == 404
    assert client.patch(f"/api/v1/evidence/{evidence_b.id}/", {"title": "x"}, format="json").status_code in (403, 404)
    assert client.delete(f"/api/v1/evidence/{evidence_b.id}/").status_code in (403, 404)
    assert Evidence.all_objects.filter(pk=evidence_b.id).exists()
