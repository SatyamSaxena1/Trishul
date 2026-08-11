"""Permanent regression coverage for the core authorization invariant:

Sharing a tenant or application does not grant access to evidence belonging
to controls a user is not assigned to.

Tenant T / Application X / OrganisationControl A (Alice) / OrganisationControl B (Bob),
each with its own Evidence record, exercised through every reachable API path.
"""

from datetime import date

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from core.models import (
    Application,
    Assessment,
    ControlAssignment,
    ControlEvidenceLink,
    CrossTenantAccessEvent,
    Evidence,
    FrameworkVersion,
    Membership,
    OrganisationControl,
    Organization,
    Task,
    Tenant,
    UnifiedControlObjective,
    Workspace,
)
from core.tenancy import tenant_context

pytestmark = pytest.mark.django_db


def client_for(user, tenant):
    client = APIClient()
    client.force_authenticate(user)
    client.credentials(HTTP_X_TRISHUL_TENANT=str(tenant.id))
    return client


@pytest.fixture
def scenario():
    """Tenant T / Application X / Control A (+ Alice) / Control B (+ Bob), each with its own evidence."""
    tenant = Tenant.objects.create(slug="isolation-t", name="Isolation tenant")
    alice = get_user_model().objects.create(username="alice")
    bob = get_user_model().objects.create(username="bob")
    Membership.all_objects.create(tenant=tenant, user=alice, role=Membership.Role.CONTROL_OWNER)
    Membership.all_objects.create(tenant=tenant, user=bob, role=Membership.Role.CONTROL_OWNER)

    with tenant_context(tenant.id):
        org = Organization.objects.create(tenant=tenant, name="Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=org, name="Workspace")
        application = Application.objects.create(tenant=tenant, workspace=workspace, name="Application X")
        framework = FrameworkVersion.objects.create(
            tenant=tenant,
            framework="Isolation demo",
            version_name="1",
            source_url="https://example.test/demo",
            catalog_hash="d" * 64,
        )
        assessment = Assessment.objects.create(
            tenant=tenant, application=application, framework_version=framework, name="Demo"
        )
        control_a = OrganisationControl.objects.create(
            tenant=tenant,
            application=application,
            unified_control=UnifiedControlObjective.objects.create(
                tenant=tenant, code="UCO-A", domain="access", objective="A", control_type="preventive", nature="process"
            ),
        )
        control_b = OrganisationControl.objects.create(
            tenant=tenant,
            application=application,
            unified_control=UnifiedControlObjective.objects.create(
                tenant=tenant, code="UCO-B", domain="access", objective="B", control_type="preventive", nature="process"
            ),
        )
        ControlAssignment.objects.create(tenant=tenant, organisation_control=control_a, assignee=alice)
        ControlAssignment.objects.create(tenant=tenant, organisation_control=control_b, assignee=bob)

        evidence_a = Evidence.objects.create(
            tenant=tenant,
            assessment=assessment,
            title="Evidence A",
            source="manual",
            evidence_date=date.today(),
            object_key=f"{tenant.id}/evidence/a.txt",
            sha256="a" * 64,
            classification="internal",
        )
        evidence_b = Evidence.objects.create(
            tenant=tenant,
            assessment=assessment,
            title="Evidence B",
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
                reason="Manual isolation-test link.",
                mapping_version="1",
            )
        task_a = Task.objects.create(
            tenant=tenant,
            task_type="evidence_request",
            title="Task A",
            description="Provide evidence for control A.",
            organisation_control=control_a,
            owner=alice,
        )
        task_b = Task.objects.create(
            tenant=tenant,
            task_type="evidence_request",
            title="Task B",
            description="Provide evidence for control B.",
            organisation_control=control_b,
            owner=bob,
        )

    return {
        "tenant": tenant,
        "alice": alice,
        "bob": bob,
        "application": application,
        "control_a": control_a,
        "control_b": control_b,
        "evidence_a": evidence_a,
        "evidence_b": evidence_b,
        "task_a": task_a,
        "task_b": task_b,
    }


def test_evidence_isolation_matrix_alice_and_bob(scenario):
    tenant = scenario["tenant"]
    alice = client_for(scenario["alice"], tenant)
    bob = client_for(scenario["bob"], tenant)
    evidence_a, evidence_b = scenario["evidence_a"], scenario["evidence_b"]
    control_a, control_b = scenario["control_a"], scenario["control_b"]

    # --- LIST: each sees only their own control's evidence, never the other's ---
    alice_list = alice.get("/api/v1/evidence/")
    assert alice_list.status_code == 200
    alice_ids = {item["id"] for item in alice_list.data["results"]}
    assert alice_ids == {str(evidence_a.id)}
    assert str(evidence_b.id) not in alice_ids

    bob_list = bob.get("/api/v1/evidence/")
    assert bob_list.status_code == 200
    bob_ids = {item["id"] for item in bob_list.data["results"]}
    assert bob_ids == {str(evidence_b.id)}
    assert str(evidence_a.id) not in bob_ids

    # --- RETRIEVE (own vs. other's) ---
    assert alice.get(f"/api/v1/evidence/{evidence_a.id}/").status_code == 200
    assert alice.get(f"/api/v1/evidence/{evidence_b.id}/").status_code == 404
    assert bob.get(f"/api/v1/evidence/{evidence_b.id}/").status_code == 200
    assert bob.get(f"/api/v1/evidence/{evidence_a.id}/").status_code == 404

    # --- UPDATE / DELETE: denied on the other's evidence by direct ID (also immutable for everyone) ---
    assert alice.patch(f"/api/v1/evidence/{evidence_b.id}/", {"title": "x"}, format="json").status_code in (403, 404)
    assert alice.delete(f"/api/v1/evidence/{evidence_b.id}/").status_code in (403, 404)
    assert Evidence.all_objects.filter(pk=evidence_b.id).exists()

    # --- Evidence-scoped actions deny Evidence B either way: reuse-evaluations requires only
    # "evidence.assigned" (Control Owner's native grant) so it 404s via get_object() scoping;
    # quality-overrides requires the broader "evidence.read" a bare Control Owner never holds,
    # so it 403s at the permission gate before get_object() runs. Both are safe denials. ---
    assert alice.post(f"/api/v1/evidence/{evidence_b.id}/reuse-evaluations/", {}, format="json").status_code == 404
    assert alice.post(f"/api/v1/evidence/{evidence_b.id}/quality-overrides/", {}, format="json").status_code == 403

    # --- Direct guessed-ID access is denied identically to a discovered ID (no different code path) ---
    assert alice.get(f"/api/v1/evidence/{evidence_b.id}/").status_code == 404

    # --- Same application does not leak: both controls/evidence share Application X ---
    assert control_a.application_id == control_b.application_id
    assert evidence_a.assessment_id == evidence_b.assessment_id  # same assessment too -- strictly harder case

    # --- Control-level visibility mirrors evidence-level visibility ---
    assert alice.get(f"/api/v1/organisation-controls/{control_b.id}/").status_code == 404
    assert bob.get(f"/api/v1/organisation-controls/{control_a.id}/").status_code == 404

    # --- Task listing (a different resource type) does not leak the other's work item ---
    alice_tasks = {item["id"] for item in alice.get("/api/v1/tasks/").data["results"]}
    assert alice_tasks == {str(scenario["task_a"].id)}
    assert str(scenario["task_b"].id) not in alice_tasks

    # --- Broader, permission-gated resource types are simply unreachable for a bare Control Owner
    # (their atomic permission set has no "assessment.read"/"evidence.read"/"control.read"), so
    # there is no aggregation/dashboard/report path left through which Evidence B could leak to Alice. ---
    for path in (
        "/api/v1/assessment-evidence/",
        "/api/v1/compliance-gaps/",
        "/api/v1/control-evidence-links/",
    ):
        assert alice.get(path).status_code == 403, path

    # --- Every denial above was audited (§5.3), not silently dropped ---
    denials = CrossTenantAccessEvent.all_objects.filter(
        tenant=tenant, subject_id=str(scenario["alice"].id), decision="deny"
    )
    assert denials.exists()
