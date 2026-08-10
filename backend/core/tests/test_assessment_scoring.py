from datetime import date

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework.test import APIClient

from core.models import (
    AssessmentResponse,
    AuditorVerdict,
    ControlEvidenceLink,
    Evidence,
    EvidenceReuseEvaluation,
    FrameworkControlMapping,
    Membership,
    OrganisationControl,
    Requirement,
    UnifiedControlObjective,
)
from core.tenancy import tenant_context
from core.tests.test_evidence import evidence_setup

pytestmark = pytest.mark.django_db


def test_not_applicable_requires_justification_and_is_excluded_from_score():
    tenant, assessment, _ = evidence_setup()
    user = get_user_model().objects.create(username="assessor")
    Membership.all_objects.create(tenant=tenant, user=user, role=Membership.Role.ASSESSOR)
    with tenant_context(tenant.id):
        requirement = Requirement.objects.create(
            tenant=tenant,
            framework_version=assessment.framework_version,
            control_id="A.5.1",
            title="Policies for information security",
            requirement="Policies must be defined and reviewed.",
        )
        response = AssessmentResponse.objects.create(
            tenant=tenant,
            assessment=assessment,
            requirement=requirement,
        )
        with pytest.raises(ValidationError, match="require justification"):
            AssessmentResponse.objects.create(
                tenant=tenant,
                assessment=assessment,
                requirement=Requirement.objects.create(
                    tenant=tenant,
                    framework_version=assessment.framework_version,
                    control_id="A.5.2",
                    title="Roles",
                    requirement="Roles must be assigned.",
                ),
                decision=AssessmentResponse.Decision.NOT_APPLICABLE,
            )

    client = APIClient()
    client.force_authenticate(user)
    url = f"/api/v1/assessment-responses/{response.id}/"
    assert client.patch(url, {"decision": "not_applicable"}, format="json", HTTP_IF_MATCH="1").status_code == 400
    decided = client.patch(
        url,
        {"decision": "not_applicable", "rationale": "The service has no physical premises."},
        format="json",
        HTTP_IF_MATCH="1",
    )
    assert decided.status_code == 200, decided.data
    assert decided.data["reviewed_by"] == user.id

    with tenant_context(tenant.id):
        for index, decision in enumerate(("compliant", "partial", "noncompliant"), start=3):
            item = Requirement.objects.create(
                tenant=tenant,
                framework_version=assessment.framework_version,
                control_id=f"A.5.{index}",
                title=f"Requirement {index}",
                requirement="Test requirement.",
            )
            AssessmentResponse.objects.create(
                tenant=tenant,
                assessment=assessment,
                requirement=item,
                decision=decision,
                rationale="Reviewed.",
            )

    score = client.get(f"/api/v1/assessments/{assessment.id}/score/")
    assert score.status_code == 200, score.data
    assert score.data["assessment_id"] == str(assessment.id)
    assert score.data["score"] == "37.50"
    assert score.data["applicable_responses"] == 4
    assert score.data["excluded_not_applicable"] == 1
    assert score.data["counts"] == {
        "compliant": 1,
        "noncompliant": 1,
        "not_applicable": 1,
        "not_assessed": 1,
        "partially_compliant": 1,
    }
    assert len(score.data["contributions"]) == 5


def test_weighted_human_verdict_score_applies_critical_cap_and_drills_to_evidence():
    tenant, assessment, _ = evidence_setup()
    ciso = get_user_model().objects.create(username="score-ciso")
    Membership.all_objects.create(tenant=tenant, user=ciso, role=Membership.Role.CISO)
    with tenant_context(tenant.id):
        evidence = Evidence.objects.create(
            tenant=tenant,
            assessment=assessment,
            title="Policy",
            source="manual",
            evidence_date=date.today(),
            object_key=f"{tenant.id}/evidence/scoring.txt",
            sha256="7" * 64,
            classification="internal",
        )
        for index in range(9):
            requirement = Requirement.objects.create(
                tenant=tenant,
                framework_version=assessment.framework_version,
                control_id=f"SCORE-{index}",
                title=f"Scoring requirement {index}",
                requirement="Demonstration requirement.",
                criticality="critical" if index == 0 else "low",
            )
            uco = UnifiedControlObjective.objects.create(
                tenant=tenant,
                code=f"UCO-SCORE-{index}",
                domain="governance",
                objective=f"Scoring objective {index}.",
                control_type="preventive",
                nature="process",
            )
            mapping = FrameworkControlMapping.objects.create(
                tenant=tenant, requirement=requirement, unified_control=uco, coverage="full"
            )
            control = OrganisationControl.objects.create(
                tenant=tenant, application=assessment.application, unified_control=uco
            )
            AuditorVerdict.objects.create(
                tenant=tenant,
                engagement_id="00000000-0000-0000-0000-000000000002",
                organisation_control=control,
                decision="noncompliant" if index == 0 else "compliant",
                rationale="Independent review.",
                finalized_by=ciso,
            )
            if index == 0:
                evaluation = EvidenceReuseEvaluation.objects.create(
                    tenant=tenant,
                    evidence=evidence,
                    organisation_control=control,
                    requirement=requirement,
                    unified_control=uco,
                    mapping=mapping,
                    mapping_coverage="full",
                    outcome="accept",
                    checks=[{"check": "quality_threshold", "status": "PASS"}],
                )
                ControlEvidenceLink.objects.create(
                    tenant=tenant,
                    organisation_control=control,
                    evidence=evidence,
                    source_type="reuse_evaluation",
                    source_id=evaluation.id,
                    source_hash=evidence.sha256,
                    verdict="accept",
                    reason="Checks passed.",
                    mapping_version="1",
                )

    client = APIClient()
    client.force_authenticate(ciso)
    result = client.get(f"/api/v1/assessments/{assessment.id}/score/")

    assert result.status_code == 200, result.data
    assert result.data["raw_score"] == "72.73"
    assert result.data["score"] == "70.00"
    assert result.data["critical_cap_applied"] is True
    critical = next(item for item in result.data["contributions"] if item["criticality"] == "critical")
    assert critical["human_verdict_id"]
    assert critical["reuse_evaluation_id"] == str(evaluation.id)
    assert critical["evidence_id"] == str(evidence.id)
    assert critical["evidence_version"] == 1
