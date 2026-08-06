"""One API-driven SaaS journey from platform onboarding to CISO posture."""

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import Membership, OrganisationControl, Tenant
from core.tenancy import tenant_context
from deployment_assurance.models import ControlResult

from .conftest import terraform_plan

pytestmark = pytest.mark.django_db

OPEN_SSH = (
    "aws_security_group.bastion",
    "aws_security_group",
    {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
)


def _member(tenant, role, username):
    user = get_user_model().objects.create(username=username)
    Membership.all_objects.create(tenant=tenant, user=user, role=role)
    return user


def test_platform_to_auditor_to_ciso_journey(target, submit, run_evaluation):
    target.tenant.tenant_type = Tenant.Type.AUDITEE
    target.tenant.auditee_mode = Tenant.AuditeeMode.SELF_SERVICE
    target.tenant.save(update_fields=["tenant_type", "auditee_mode", "updated_at"])

    platform = Tenant.objects.create(slug="platform", name="Trishul Cloud", tenant_type=Tenant.Type.PLATFORM)
    platform_admin = _member(platform, Membership.Role.PLATFORM_ADMIN, "platform-admin-journey")
    client = APIClient()
    client.force_authenticate(platform_admin)
    created = client.post(
        "/api/v1/tenant-admin/",
        {
            "slug": "journey-firm",
            "name": "Journey Audit Firm",
            "administrator_email": "firm-admin@example.test",
            "plan_key": "pilot",
            "entitlements": {
                "auditor_seats": 5,
                "auditee_organisations": 5,
                "frameworks": ["ISO/IEC 27002:2022"],
                "evidence_bytes": 10000000,
                "deployment_evaluations": 100,
                "ai_credits": 10000,
                "connectors": True,
                "vendor_assessments": False,
            },
        },
        format="json",
    )
    assert created.status_code == 201, created.data
    firm = Tenant.objects.get(pk=created.json()["id"])
    firm_admin = _member(firm, Membership.Role.FIRM_ADMIN, "firm-admin-journey")
    auditor = _member(firm, Membership.Role.AUDITOR, "auditor-journey")

    client.force_authenticate(firm_admin)
    invited = client.post(
        "/api/v1/tenant-invitations/",
        {
            "email": "second-auditor@example.test",
            "role": Membership.Role.AUDITOR,
            "expires_at": (timezone.now() + timedelta(days=7)).isoformat(),
        },
        format="json",
    )
    assert invited.status_code == 201, invited.data
    assert (
        client.post(
            "/api/v1/engagements/link-auditee/",
            {"auditee_tenant_id": str(target.tenant_id)},
            format="json",
        ).status_code
        == 201
    )
    today = timezone.localdate()
    engagement_response = client.post(
        "/api/v1/engagements/",
        {
            "auditee_tenant": str(target.tenant_id),
            "name": "Production deployment audit",
            "reference": "JOURNEY-001",
            "status": "active",
            "starts_on": str(today),
            "ends_on": str(today + timedelta(days=30)),
            "framework_scope": ["ISO/IEC 27002:2022"],
            "application_scope": [str(target.application_id)],
            "control_scope": [],
        },
        format="json",
    )
    assert engagement_response.status_code == 201, engagement_response.data
    engagement_id = engagement_response.json()["id"]
    assigned = client.post(
        "/api/v1/engagement-members/",
        {"engagement": engagement_id, "user": auditor.id, "role": "auditor"},
        format="json",
    )
    assert assigned.status_code == 201, assigned.data

    run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    with tenant_context(target.tenant_id):
        result = ControlResult.objects.select_related("policy_rule").get(
            evaluation_run=run, reason_code="PUBLIC_ADMIN_PORT"
        )
        control = OrganisationControl.objects.get(
            application=target.application, unified_control=result.policy_rule.unified_control
        )

    client.force_authenticate(auditor)
    review = client.get(f"/api/v1/engagements/{engagement_id}/assurance-results/")
    assert review.status_code == 200 and review.json()[0]["related_gap_ids"]
    verdict = client.post(
        f"/api/v1/engagements/{engagement_id}/verdicts/",
        {
            "organisation_control_id": str(control.id),
            "evidence_result_id": str(result.id),
            "decision": "noncompliant",
            "rationale": "Public administrative access was verified in deployment evidence.",
        },
        format="json",
    )
    assert verdict.status_code == 201 and verdict.json()["locked"] is True

    ciso = _member(target.tenant, Membership.Role.CISO, "ciso-journey")
    client.force_authenticate(ciso)
    assert client.get("/api/v1/organisation-controls/").json()["results"]
    assert client.get("/api/v1/compliance-gaps/").json()["results"]
    assert client.get("/api/v1/risks/").json()["results"]
    assert client.get("/api/v1/tasks/").json()["results"]
