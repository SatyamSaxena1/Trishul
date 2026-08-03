import uuid

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from core.models import (
    Application,
    AuditEvent,
    Finding,
    FindingReview,
    Membership,
    Organization,
    Repository,
    RepositoryVersion,
    Scan,
    Tenant,
    Workspace,
)
from core.tenancy import tenant_context


def make_finding(tenant):
    suffix = uuid.uuid4().hex[:8]
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name=f"Org {suffix}")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name=f"Workspace {suffix}")
        application = Application.objects.create(tenant=tenant, workspace=workspace, name=f"App {suffix}")
        repository = Repository.objects.create(tenant=tenant, application=application, name=f"Repo {suffix}")
        version = RepositoryVersion.objects.create(
            tenant=tenant,
            repository=repository,
            object_key="source.zip",
            sha256="a" * 64,
            size=1,
            manifest={"files": 1},
        )
        scan = Scan.objects.create(
            tenant=tenant,
            repository_version=version,
            language_pack="python-stdlib",
            language_pack_version="1.0",
            coverage={"files": 1},
        )
        return Finding.objects.create(
            tenant=tenant,
            scan=scan,
            rule_id="PY001",
            rule_version="1.0",
            language="python",
            title="Shell injection",
            description="Unsafe shell invocation",
            severity=4,
            confidence=4,
            fingerprint="b" * 64,
        )


@pytest.mark.django_db
def test_human_review_is_required_validated_and_audited():
    tenant = Tenant.objects.create(slug="pilot", name="Pilot")
    finding = make_finding(tenant)
    reviewer = get_user_model().objects.create_user(username="reviewer")
    Membership.all_objects.create(tenant=tenant, user=reviewer, role=Membership.Role.APPSEC)
    client = APIClient()
    client.force_authenticate(reviewer)
    headers = {"HTTP_X_TRISHUL_TENANT": str(tenant.id)}

    missing = client.post("/api/v1/finding-reviews/", {"finding": finding.id}, format="json", **headers)
    assert missing.status_code == 400
    invalid = client.post(
        "/api/v1/finding-reviews/",
        {"finding": finding.id, "decision": "confirmed", "reviewer_comment": "x" * 2001},
        format="json",
        **headers,
    )
    assert invalid.status_code == 400
    response = client.post(
        "/api/v1/finding-reviews/",
        {
            "finding": finding.id,
            "decision": "accepted",
            "reason_codes": ["confirmed_exploitable"],
            "reviewer_comment": "Reproduced by the reviewer.",
        },
        format="json",
        **headers,
    )
    assert response.status_code == 201
    review = FindingReview.all_objects.get()
    assert review.reviewer == reviewer
    assert review.finding_provenance["fingerprint"] == finding.fingerprint
    event = AuditEvent.all_objects.get(action="finding.reviewed")
    assert event.details["reviewer_id"] == str(reviewer.id)


@pytest.mark.django_db
def test_usefulness_uses_latest_conclusive_decisions_and_separates_other_outcomes():
    tenant = Tenant.objects.create(slug="pilot", name="Pilot")
    reviewer = get_user_model().objects.create_user(username="reviewer")
    Membership.all_objects.create(tenant=tenant, user=reviewer, role=Membership.Role.APPSEC)
    findings = [make_finding(tenant) for _ in range(4)]
    with tenant_context(tenant.id):
        for finding, decision in zip(
            findings, ["accepted", "false_positive", "duplicate", "needs_context"], strict=True
        ):
            FindingReview.objects.create(
                tenant=tenant,
                finding=finding,
                reviewer=reviewer,
                decision=decision,
                finding_provenance={"finding_id": str(finding.id)},
            )
    client = APIClient()
    client.force_authenticate(reviewer)
    response = client.get("/api/v1/findings/pilot-usefulness/", HTTP_X_TRISHUL_TENANT=str(tenant.id))
    assert response.status_code == 200
    assert response.json() == {
        "accepted": 1,
        "false_positive": 1,
        "duplicate": 1,
        "needs_context": 1,
        "conclusive_decisions": 2,
        "usefulness": 0.5,
        "definition": "accepted / (accepted + false_positive)",
    }
