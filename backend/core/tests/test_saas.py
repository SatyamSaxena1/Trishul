from datetime import date, timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import (
    Application,
    Assessment,
    AuditorVerdict,
    ControlEvidenceLink,
    CrossTenantAccessEvent,
    Engagement,
    EngagementMember,
    Evidence,
    FrameworkControlMapping,
    FrameworkVersion,
    Membership,
    OrganisationControl,
    Organization,
    Tenant,
    TenantEntitlement,
    TenantRelationship,
    TenantSubscription,
    UnifiedControlObjective,
    Workspace,
)
from core.tenancy import tenant_context
from deployment_assurance.models import (
    Decision,
    DeploymentDecision,
    DeploymentSnapshot,
    DeploymentTarget,
    Environment,
    EvaluationRun,
    Provider,
    SourceType,
)
from deployment_assurance.policy.registry import sync_pack

pytestmark = pytest.mark.django_db


def make_application(tenant, name="Payments"):
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name=f"{name} Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name="Default")
        return Application.objects.create(tenant=tenant, workspace=workspace, name=name)


def member(tenant, role, username):
    user = get_user_model().objects.create(username=username)
    Membership.all_objects.create(tenant=tenant, user=user, role=role)
    return user


def engagement_for(firm, auditee, creator, *, application=None):
    today = timezone.localdate()
    with tenant_context(firm.id):
        return Engagement.objects.create(
            tenant=firm,
            auditee_tenant=auditee,
            name="FY27 deployment audit",
            reference="FY27-001",
            status=Engagement.Status.ACTIVE,
            starts_on=today - timedelta(days=1),
            ends_on=today + timedelta(days=30),
            framework_scope=["ISO/IEC 27002:2022"],
            application_scope=[str(application.id)] if application else [],
            created_by=creator,
            approved_by=creator,
        )


def assurance_decision(tenant, application):
    with tenant_context(tenant.id):
        pack = sync_pack(tenant)
        from deployment_assurance.models import DecisionThresholdProfile

        threshold = DecisionThresholdProfile.objects.create(tenant=tenant, name="default", is_default=True)
        target = DeploymentTarget.objects.create(
            tenant=tenant,
            application=application,
            name="Production",
            slug="production",
            provider=Provider.AWS,
            target_type=DeploymentTarget.TargetType.IAC_DEPLOYMENT,
            environment=Environment.PRODUCTION,
            external_id="prod",
        )
        snapshot = DeploymentSnapshot.objects.create(
            tenant=tenant,
            target=target,
            source_type=SourceType.TERRAFORM_PLAN,
            artifact_object_key=f"{tenant.id}/artifact",
            artifact_sha256="a" * 64,
            artifact_size=2,
            collected_by_type=DeploymentSnapshot.CollectorType.SYSTEM,
            ingestion_state=DeploymentSnapshot.IngestionState.READY,
        )
        run = EvaluationRun.objects.create(
            tenant=tenant,
            snapshot=snapshot,
            target=target,
            policy_pack=pack,
            requested_by_type=DeploymentSnapshot.CollectorType.SYSTEM,
            state=EvaluationRun.State.COMPLETED,
        )
        return DeploymentDecision.objects.create(
            tenant=tenant,
            evaluation_run=run,
            target=target,
            threshold_profile=threshold,
            decision=Decision.APPROVED,
            compliance_score=100,
            risk_score=0,
            reason_codes=["ALL_MANDATORY_CONTROLS_PASSED"],
            counts={"pass": 1},
            decision_hash="b" * 64,
        )


def test_platform_onboards_an_enforced_audit_firm():
    platform = Tenant.objects.create(slug="platform", name="Trishul Cloud", tenant_type=Tenant.Type.PLATFORM)
    admin = member(platform, Membership.Role.PLATFORM_ADMIN, "platform-admin")
    client = APIClient()
    client.force_authenticate(admin)
    response = client.post(
        "/api/v1/tenant-admin/",
        {
            "slug": "example-audit",
            "name": "Example Audit",
            "administrator_email": "admin@example.test",
            "plan_key": "pilot",
            "entitlements": {
                "auditor_seats": 3,
                "auditee_organisations": 2,
                "frameworks": ["ISO/IEC 27002:2022"],
                "evidence_bytes": 1000000,
                "deployment_evaluations": 20,
                "ai_credits": 10000,
                "connectors": True,
                "vendor_assessments": False,
            },
        },
        format="json",
    )
    assert response.status_code == 201, response.data
    firm = Tenant.objects.get(slug="example-audit")
    assert firm.tenant_type == Tenant.Type.AUDIT_FIRM
    with tenant_context(firm.id):
        assert TenantSubscription.objects.get().state == TenantSubscription.State.TRIAL
        assert TenantEntitlement.objects.get(code="auditor_seats").limit == 3


def test_relationship_alone_never_grants_auditee_visibility():
    firm = Tenant.objects.create(slug="firm", name="Firm", tenant_type=Tenant.Type.AUDIT_FIRM)
    auditee = Tenant.objects.create(slug="auditee", name="Auditee", tenant_type=Tenant.Type.AUDITEE)
    application = make_application(auditee)
    user = member(firm, Membership.Role.AUDIT_MANAGER, "manager")
    with tenant_context(firm.id):
        TenantRelationship.objects.create(
            tenant=firm, related_tenant=auditee, relationship=TenantRelationship.Relationship.MANAGES
        )
    client = APIClient()
    client.force_authenticate(user)
    response = client.get("/api/v1/applications/")
    assert response.status_code == 403
    assert Application.all_objects.filter(pk=application.id).exists()


@pytest.mark.parametrize("inactive", ["expired", Engagement.Status.CLOSED, Engagement.Status.REVOKED])
def test_engagement_access_is_scoped_and_revoked_immediately(inactive):
    firm = Tenant.objects.create(slug="firm", name="Firm", tenant_type=Tenant.Type.AUDIT_FIRM)
    auditee = Tenant.objects.create(slug="auditee", name="Auditee", tenant_type=Tenant.Type.AUDITEE)
    application = make_application(auditee)
    decision = assurance_decision(auditee, application)
    auditor = member(firm, Membership.Role.AUDITOR, f"auditor-{inactive}")
    manager = member(firm, Membership.Role.AUDIT_MANAGER, f"manager-{inactive}")
    engagement = engagement_for(firm, auditee, manager, application=application)
    with tenant_context(firm.id):
        EngagementMember.objects.create(
            tenant=firm, engagement=engagement, user=auditor, role=EngagementMember.Role.AUDITOR
        )

    client = APIClient()
    client.force_authenticate(auditor)
    url = f"/api/v1/engagements/{engagement.id}/assurance-results/"
    allowed = client.get(url)
    assert allowed.status_code == 200, allowed.data
    assert allowed.json()[0]["id"] == str(decision.id)

    with tenant_context(firm.id):
        if inactive == "expired":
            Engagement.all_objects.filter(pk=engagement.id).update(ends_on=timezone.localdate() - timedelta(days=1))
        else:
            Engagement.all_objects.filter(pk=engagement.id).update(status=inactive)
    denied = client.get(url)
    assert denied.status_code == 403
    events = CrossTenantAccessEvent.all_objects.filter(tenant=firm, engagement=engagement).order_by("occurred_at")
    assert [event.decision for event in events] == ["allow", "deny"]


def test_unassigned_auditor_and_reviewer_writes_are_denied_and_logged():
    firm = Tenant.objects.create(slug="firm", name="Firm", tenant_type=Tenant.Type.AUDIT_FIRM)
    auditee = Tenant.objects.create(slug="auditee", name="Auditee", tenant_type=Tenant.Type.AUDITEE)
    application = make_application(auditee)
    manager = member(firm, Membership.Role.AUDIT_MANAGER, "manager")
    unassigned = member(firm, Membership.Role.AUDITOR, "unassigned")
    reviewer = member(firm, Membership.Role.REVIEWER, "reviewer")
    engagement = engagement_for(firm, auditee, manager, application=application)
    with tenant_context(auditee.id):
        uco = UnifiedControlObjective.objects.create(
            tenant=auditee,
            code="UCO-NET-007",
            domain="network",
            objective="Restrict public administrative access.",
            control_type=UnifiedControlObjective.ControlType.PREVENTIVE,
            nature=UnifiedControlObjective.Nature.TECHNICAL,
        )
        control = OrganisationControl.objects.create(tenant=auditee, application=application, unified_control=uco)
    with tenant_context(firm.id):
        EngagementMember.objects.create(
            tenant=firm, engagement=engagement, user=reviewer, role=EngagementMember.Role.REVIEWER
        )

    client = APIClient()
    client.force_authenticate(unassigned)
    assert client.get(f"/api/v1/engagements/{engagement.id}/assurance-results/").status_code == 403
    client.force_authenticate(reviewer)
    response = client.post(
        f"/api/v1/engagements/{engagement.id}/verdicts/",
        {"organisation_control_id": str(control.id), "decision": "compliant", "rationale": "Reviewed."},
        format="json",
    )
    assert response.status_code == 403
    assert CrossTenantAccessEvent.all_objects.filter(tenant=firm, decision="deny").count() == 2


def test_auditor_verdict_lock_requires_reasoned_manager_unlock():
    firm = Tenant.objects.create(slug="firm", name="Firm", tenant_type=Tenant.Type.AUDIT_FIRM)
    auditee = Tenant.objects.create(slug="auditee", name="Auditee", tenant_type=Tenant.Type.AUDITEE)
    application = make_application(auditee)
    auditor = member(firm, Membership.Role.AUDITOR, "auditor")
    manager = member(firm, Membership.Role.AUDIT_MANAGER, "manager")
    compliance_manager = member(auditee, Membership.Role.COMPLIANCE_MANAGER, "compliance-manager")
    engagement = engagement_for(firm, auditee, manager, application=application)
    with tenant_context(firm.id):
        EngagementMember.objects.create(
            tenant=firm, engagement=engagement, user=auditor, role=EngagementMember.Role.AUDITOR
        )
    with tenant_context(auditee.id):
        uco = UnifiedControlObjective.objects.create(
            tenant=auditee,
            code="UCO-NET-007",
            domain="network",
            objective="Restrict public administrative access.",
            control_type=UnifiedControlObjective.ControlType.PREVENTIVE,
            nature=UnifiedControlObjective.Nature.TECHNICAL,
        )
        control = OrganisationControl.objects.create(tenant=auditee, application=application, unified_control=uco)

    client = APIClient()
    client.force_authenticate(auditor)
    url = f"/api/v1/engagements/{engagement.id}/verdicts/"
    body = {"organisation_control_id": str(control.id), "decision": "compliant", "rationale": "Evidence reviewed."}
    assert client.post(url, body, format="json").status_code == 201
    assert client.post(url, body, format="json").status_code == 400
    review = client.get(f"/api/v1/engagements/{engagement.id}/control-reviews/")
    assert review.status_code == 200, review.data
    assert review.data[0]["locked"] is True
    assert "system_evidence_verdicts" in review.data[0]
    assert "human_auditor_verdict" in review.data[0]

    client.force_authenticate(compliance_manager)
    current = client.get(f"/api/v1/organisation-controls/{control.id}/")
    assert current.status_code == 200, current.data
    assert client.patch(
        f"/api/v1/organisation-controls/{control.id}/",
        {"applicability": "not_applicable"},
        format="json",
        HTTP_IF_MATCH=str(current.data["version"]),
    ).status_code == 403

    client.force_authenticate(manager)
    unlock = client.post(
        f"/api/v1/engagements/{engagement.id}/unlock-control/",
        {"organisation_control_id": str(control.id), "reason": "New deployment evidence arrived."},
        format="json",
    )
    assert unlock.status_code == 201, unlock.data
    client.force_authenticate(auditor)
    assert client.post(url, body, format="json").status_code == 201
    with tenant_context(auditee.id):
        verdicts = list(AuditorVerdict.objects.filter(organisation_control=control).order_by("finalized_at"))
    assert [item.locked for item in verdicts] == [True, False, True]


def test_evidence_uploader_cannot_record_same_control_verdict():
    firm = Tenant.objects.create(slug="sod-firm", name="Firm", tenant_type=Tenant.Type.AUDIT_FIRM)
    auditee = Tenant.objects.create(slug="sod-auditee", name="Auditee", tenant_type=Tenant.Type.AUDITEE)
    application = make_application(auditee)
    uploader = member(firm, Membership.Role.AUDITOR, "uploader-auditor")
    independent = member(firm, Membership.Role.AUDITOR, "independent-auditor")
    manager = member(firm, Membership.Role.AUDIT_MANAGER, "sod-manager")
    engagement = engagement_for(firm, auditee, manager, application=application)
    with tenant_context(firm.id):
        for user in (uploader, independent):
            EngagementMember.objects.create(
                tenant=firm, engagement=engagement, user=user, role=EngagementMember.Role.AUDITOR
            )
    with tenant_context(auditee.id):
        framework = FrameworkVersion.objects.create(
            tenant=auditee,
            framework="Demo",
            version_name="1",
            source_url="https://example.test/demo",
            catalog_hash="a" * 64,
        )
        assessment = Assessment.objects.create(
            tenant=auditee, application=application, framework_version=framework, name="Demo"
        )
        uco = UnifiedControlObjective.objects.create(
            tenant=auditee,
            code="UCO-SOD-1",
            domain="access",
            objective="Independent evidence review.",
            control_type="preventive",
            nature="process",
        )
        control = OrganisationControl.objects.create(tenant=auditee, application=application, unified_control=uco)
        evidence = Evidence.objects.create(
            tenant=auditee,
            assessment=assessment,
            title="Submitted policy",
            source="manual",
            evidence_date=date.today(),
            object_key=f"{auditee.id}/evidence/sod.txt",
            sha256="9" * 64,
            classification="internal",
            submitted_by=uploader,
        )
        ControlEvidenceLink.objects.create(
            tenant=auditee,
            organisation_control=control,
            evidence=evidence,
            source_type="manual",
            source_id=evidence.id,
            source_hash=evidence.sha256,
            verdict="accept",
            reason="Manual test link.",
            mapping_version="1",
        )

    url = f"/api/v1/engagements/{engagement.id}/verdicts/"
    body = {"organisation_control_id": str(control.id), "decision": "compliant", "rationale": "Reviewed."}
    client = APIClient()
    client.force_authenticate(uploader)
    assert client.post(url, body, format="json").status_code == 403
    assert CrossTenantAccessEvent.all_objects.filter(
        tenant=firm, subject_id=str(uploader.id), reason="evidence_submitter_separation_of_duties"
    ).exists()
    client.force_authenticate(independent)
    assert client.post(url, body, format="json").status_code == 201


def test_partial_and_ai_control_mappings_fail_closed():
    tenant = Tenant.objects.create(slug="auditee", name="Auditee", tenant_type=Tenant.Type.AUDITEE)
    with tenant_context(tenant.id):
        uco = UnifiedControlObjective.objects.create(
            tenant=tenant,
            code="UCO-IAM-011",
            domain="identity",
            objective="Authentication information is managed securely.",
            control_type=UnifiedControlObjective.ControlType.PREVENTIVE,
            nature=UnifiedControlObjective.Nature.PROCESS,
        )
        partial = FrameworkControlMapping(
            tenant=tenant,
            unified_control=uco,
            coverage=FrameworkControlMapping.Coverage.PARTIAL,
            mapping_source=FrameworkControlMapping.Source.EXPERT,
        )
        with pytest.raises(ValidationError):
            partial.full_clean(exclude={"requirement"})
        ai = FrameworkControlMapping(
            tenant=tenant,
            unified_control=uco,
            coverage=FrameworkControlMapping.Coverage.FULL,
            mapping_source=FrameworkControlMapping.Source.AI,
        )
        with pytest.raises(ValidationError):
            ai.full_clean(exclude={"requirement"})
