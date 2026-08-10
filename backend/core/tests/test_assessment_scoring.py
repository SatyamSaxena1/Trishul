import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework.test import APIClient

from core.models import AssessmentResponse, Membership, Requirement
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
    assert score.data == {
        "assessment_id": str(assessment.id),
        "score": "50.00",
        "applicable_responses": 3,
        "excluded_not_applicable": 1,
        "counts": {"compliant": 1, "noncompliant": 1, "not_applicable": 1, "partial": 1},
    }
