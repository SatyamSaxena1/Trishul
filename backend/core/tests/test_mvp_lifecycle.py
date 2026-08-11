from datetime import date
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APIClient

from core.models import (
    Assessment,
    AuditEvent,
    ComplianceGap,
    ControlEvidenceLink,
    Engagement,
    Evidence,
    EvidenceReuseEvaluation,
    Membership,
    OrganisationControl,
    PostClosureEvidenceChange,
    Task,
    Tenant,
    UnifiedControlObjective,
)
from core.tenancy import tenant_context

pytestmark = pytest.mark.django_db


def _client(username):
    client = APIClient()
    client.force_authenticate(get_user_model().objects.get(username=username))
    return client


def _policy(length):
    return SimpleUploadedFile(
        f"policy-{length}.txt",
        (
            "Issue Date: 2026-01-01\nEffective Date: 2026-01-02\nReview Date: 2026-12-31\n"
            "Approved By: CISO\nSigned by CISO\nScope: Payments API\n"
            f"Period Covered: 2026-01-01 to 2026-12-31\nPassword Minimum Length: {length}\n"
        ).encode(),
        content_type="text/plain",
    )


@override_settings(DEBUG=True, TRISHUL_DEV_AUTH=True)
@patch("core.views.put_file")
def test_distinct_personas_complete_the_evidence_to_locked_verdict_loop(_put_file):
    call_command("seed_dev")
    platform = get_user_model().objects.get(username="dev-platform-admin")
    owner = _client("dev-control-owner")
    manager = _client("dev-compliance-manager")
    auditor = _client("dev-auditor")
    audit_manager = _client("dev-audit-manager")
    ciso = _client("dev-ciso")
    auditee = Tenant.objects.get(slug="dev-auditee")
    firm = Tenant.objects.get(slug="dev-firm")
    assert Membership.all_objects.filter(user=platform, tenant__slug="dev-platform").exists()

    with tenant_context(auditee.id):
        assessment = Assessment.objects.get(framework_version__framework="ISO-like access demo")
        requirement = assessment.framework_version.requirements.get()
        control = OrganisationControl.objects.get(unified_control__code="UCO-DEV-IAM-001")
        unrelated_uco = UnifiedControlObjective.objects.create(
            tenant=auditee,
            code="UCO-UNRELATED",
            domain="network",
            objective="Unrelated control.",
            control_type="preventive",
            nature="technical",
        )
        unrelated = OrganisationControl.objects.create(
            tenant=auditee, application=assessment.application, unified_control=unrelated_uco
        )
        unrelated_evidence = Evidence.objects.create(
            tenant=auditee,
            assessment=assessment,
            title="Unrelated control evidence",
            source="manual",
            evidence_date=date.today(),
            object_key=f"{auditee.id}/evidence/unrelated.txt",
            sha256="9" * 64,
            classification="internal",
        )
        ControlEvidenceLink.objects.create(
            tenant=auditee,
            organisation_control=unrelated,
            evidence=unrelated_evidence,
            source_type="manual",
            source_id=unrelated_evidence.id,
            source_hash=unrelated_evidence.sha256,
            verdict="accept",
            reason="Manual link for the scoped-visibility acceptance check.",
            mapping_version="1",
        )
    # §4.3: a Control Owner assigned only to `control` must not see evidence that
    # belongs solely to `unrelated`, even though both controls sit in the same
    # application and assessment.
    assert owner.get(f"/api/v1/organisation-controls/{unrelated.id}/").status_code == 404
    assert owner.get(f"/api/v1/evidence/{unrelated_evidence.id}/").status_code == 404
    listed_ids = {item["id"] for item in owner.get("/api/v1/evidence/").data["results"]}
    assert str(unrelated_evidence.id) not in listed_ids

    response = manager.post(
        "/api/v1/assessment-responses/",
        {"assessment": str(assessment.id), "requirement": str(requirement.id)},
        format="json",
    )
    assert response.status_code == 201, response.data
    upload = owner.post(
        "/api/v1/evidence/uploads/",
        {
            "assessment": str(assessment.id),
            "title": "Approved access policy",
            "source": "control owner",
            "evidence_date": "2026-01-02",
            "classification": "internal",
            "file": _policy(8),
        },
        format="multipart",
    )
    assert upload.status_code == 201, upload.data
    linked = manager.post(
        "/api/v1/assessment-evidence/",
        {"response": response.data["id"], "evidence": upload.data["id"]},
        format="json",
    )
    assert linked.status_code == 201, linked.data
    evaluated = owner.post(f"/api/v1/evidence/{upload.data['id']}/reuse-evaluations/", {}, format="json")
    assert evaluated.status_code == 200, evaluated.data
    assert {item["outcome"] for item in evaluated.data} == {"accept", "partial"}
    with tenant_context(auditee.id):
        gap = ComplianceGap.objects.get(failed_check="delta_condition")
        assert gap.details["check"]["actual"] == 8
        assert gap.details["check"]["required"] == 12
        assert Task.objects.get(gap=gap).status == "open"

    replacement = owner.post(
        f"/api/v1/evidence/{upload.data['id']}/supersede/",
        {
            "title": "Approved access policy v2",
            "source": "control owner",
            "evidence_date": "2026-01-02",
            "classification": "internal",
            "file": _policy(12),
        },
        format="multipart",
    )
    assert replacement.status_code == 201, replacement.data
    with tenant_context(auditee.id):
        gap.refresh_from_db()
        assert gap.status == "closed"
        assert Task.objects.get(gap=gap).status == "completed"
        assert EvidenceReuseEvaluation.objects.filter(evidence_id=replacement.data["id"]).count() == 2

    engagement = Engagement.all_objects.get(tenant=firm, reference="DEV-ENG-001")
    verdict_url = f"/api/v1/engagements/{engagement.id}/verdicts/"
    verdict_body = {
        "organisation_control_id": str(control.id),
        "decision": "compliant",
        "rationale": "Evidence and deterministic checks reviewed independently.",
    }
    verdict = auditor.post(verdict_url, verdict_body, format="json")
    assert verdict.status_code == 201, verdict.data
    control.refresh_from_db()
    assert (
        manager.patch(
            f"/api/v1/organisation-controls/{control.id}/",
            {"applicability": "not_applicable"},
            format="json",
            HTTP_IF_MATCH=str(control.version),
        ).status_code
        == 403
    )

    third = owner.post(
        f"/api/v1/evidence/{replacement.data['id']}/supersede/",
        {
            "title": "Approved access policy v3",
            "source": "control owner",
            "evidence_date": "2026-01-02",
            "classification": "internal",
            "file": _policy(12),
        },
        format="multipart",
    )
    assert third.status_code == 201, third.data
    with tenant_context(auditee.id):
        assert PostClosureEvidenceChange.objects.filter(evidence_id=third.data["id"], status="pending").exists()
        assert AuditEvent.objects.filter(action="evidence.changed_after_closure").exists()
    review = auditor.get(f"/api/v1/engagements/{engagement.id}/control-reviews/")
    assert review.status_code == 200, review.data
    assert review.data[0]["locked"] is True
    assert review.data[0]["pending_post_closure_changes"]

    assert (
        audit_manager.post(
            f"/api/v1/engagements/{engagement.id}/unlock-control/",
            {"organisation_control_id": str(control.id), "reason": "Review successor evidence."},
            format="json",
        ).status_code
        == 201
    )
    assert auditor.post(verdict_url, verdict_body, format="json").status_code == 201
    score = ciso.get(f"/api/v1/assessments/{assessment.id}/score/")
    assert score.status_code == 200, score.data
    assert score.data["score"] == "100.00"
    assert score.data["contributions"][0]["human_verdict_id"]
    assert score.data["contributions"][0]["evidence_id"] == replacement.data["id"]
    assert Evidence.all_objects.get(pk=third.data["id"]).evidence_version == 3
