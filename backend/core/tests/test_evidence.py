from datetime import date, timedelta
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import (
    Assessment,
    AuditEvent,
    Evidence,
    FrameworkVersion,
    ServiceAccount,
    Tenant,
    TenantEntitlement,
)
from core.tenancy import tenant_context
from core.tests.test_security import make_application

pytestmark = pytest.mark.django_db


def evidence_setup():
    tenant = Tenant.objects.create(slug="auditee", name="Auditee")
    application = make_application(tenant, "Payments")
    with tenant_context(tenant.id):
        framework = FrameworkVersion.objects.create(
            tenant=tenant,
            framework="ISO 27001",
            version_name="2022",
            source_url="https://example.test/iso-27001",
            catalog_hash="a" * 64,
        )
        assessment = Assessment.objects.create(
            tenant=tenant,
            application=application,
            framework_version=framework,
            name="Annual assessment",
        )
    _, token = ServiceAccount.issue(
        tenant=tenant,
        name="evidence-writer",
        scopes=["assessment.write", "evidence.read"],
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return tenant, assessment, token


def evidence_body(*, object_key="auditee/evidence/policy-v1.pdf"):
    return {
        "title": "Access control policy",
        "source": "manual upload",
        "evidence_date": date.today().isoformat(),
        "object_key": object_key,
        "sha256": "b" * 64,
        "classification": "confidential",
    }


def test_evidence_api_creates_an_append_only_version_chain():
    tenant, assessment, token = evidence_setup()
    client = APIClient()
    headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    initial_body = {
        **evidence_body(object_key=f"{tenant.id}/evidence/policy-v1.pdf"),
        "assessment": str(assessment.id),
        "evidence_version": 99,
        "status": "superseded",
    }
    created = client.post("/api/v1/evidence/", initial_body, format="json", **headers)
    assert created.status_code == 201, created.data
    assert created.data["evidence_version"] == 1
    assert created.data["status"] == "current"
    assert created.data["supersedes"] is None

    evidence_id = created.data["id"]
    replacement = client.post(
        f"/api/v1/evidence/{evidence_id}/supersede/",
        evidence_body(object_key=f"{tenant.id}/evidence/policy-v2.pdf"),
        format="json",
        **headers,
    )
    assert replacement.status_code == 201, replacement.data
    assert replacement.data["evidence_version"] == 2
    assert str(replacement.data["supersedes"]) == evidence_id
    assert replacement.data["status"] == "current"

    original = client.get(f"/api/v1/evidence/{evidence_id}/", **headers)
    assert original.data["status"] == "superseded"
    assert client.post(
        f"/api/v1/evidence/{evidence_id}/supersede/",
        evidence_body(object_key=f"{tenant.id}/evidence/policy-v3.pdf"),
        format="json",
        **headers,
    ).status_code == 400
    assert client.patch(
        f"/api/v1/evidence/{evidence_id}/", {"title": "Changed"}, format="json", **headers
    ).status_code == 405
    assert client.delete(f"/api/v1/evidence/{evidence_id}/", **headers).status_code == 405

    with tenant_context(tenant.id):
        original_record = Evidence.objects.get(pk=evidence_id)
        assert original_record.title == "Access control policy"
        with pytest.raises(ValidationError):
            original_record.save()
        with pytest.raises(ValidationError):
            original_record.delete()
    assert list(
        AuditEvent.all_objects.filter(tenant=tenant).order_by("occurred_at", "id").values_list("action", flat=True)
    ) == [
        "created",
        "superseded",
    ]


def test_evidence_model_rejects_invalid_versions_and_reused_object_keys():
    tenant, assessment, _ = evidence_setup()
    with tenant_context(tenant.id):
        with pytest.raises(ValidationError, match="version 1"):
            Evidence.objects.create(
                tenant=tenant,
                assessment=assessment,
                evidence_version=2,
                **evidence_body(),
            )
        first = Evidence.objects.create(tenant=tenant, assessment=assessment, **evidence_body())
        with pytest.raises(ValidationError, match="new immutable object key"):
            Evidence.objects.create(
                tenant=tenant,
                assessment=assessment,
                supersedes=first,
                evidence_version=2,
                **evidence_body(),
            )


@patch("core.views.put_file")
def test_evidence_upload_hashes_bytes_and_uses_a_unique_tenant_key(put_file):
    tenant, assessment, token = evidence_setup()
    client = APIClient()
    uploaded = SimpleUploadedFile("policy.pdf", b"policy contents", content_type="application/pdf")
    response = client.post(
        "/api/v1/evidence/uploads/",
        {
            "assessment": str(assessment.id),
            "title": "Access control policy",
            "source": "manual upload",
            "evidence_date": date.today().isoformat(),
            "classification": "confidential",
            "file": uploaded,
        },
        format="multipart",
        HTTP_AUTHORIZATION=f"Bearer {token}",
    )
    assert response.status_code == 201, response.data
    assert response.data["sha256"] == "73570d63948a49a7d55815969a64ad76fb213383ea1a0f8d1755908e38ed3da0"
    assert response.data["object_key"].startswith(f"{tenant.id}/evidence/{assessment.id}/")
    put_file.assert_called_once()
    assert put_file.call_args.kwargs["content_type"] == "application/pdf"
    replacement = client.post(
        f"/api/v1/evidence/{response.data['id']}/supersede/",
        {
            "title": "Access control policy v2",
            "source": "manual upload",
            "evidence_date": date.today().isoformat(),
            "classification": "confidential",
            "file": SimpleUploadedFile("policy-v2.pdf", b"updated policy", content_type="application/pdf"),
        },
        format="multipart",
        HTTP_AUTHORIZATION=f"Bearer {token}",
    )
    assert replacement.status_code == 201, replacement.data
    assert replacement.data["evidence_version"] == 2
    assert str(replacement.data["supersedes"]) == response.data["id"]
    assert put_file.call_count == 2


@patch("core.views.put_file", side_effect=RuntimeError("storage unavailable"))
def test_evidence_upload_failure_does_not_create_a_record(_put_file):
    tenant, assessment, token = evidence_setup()
    client = APIClient()
    with pytest.raises(RuntimeError, match="storage unavailable"):
        client.post(
            "/api/v1/evidence/uploads/",
            {
                "assessment": str(assessment.id),
                "title": "Policy",
                "source": "manual upload",
                "evidence_date": date.today().isoformat(),
                "classification": "confidential",
                "file": SimpleUploadedFile("policy.pdf", b"contents"),
            },
            format="multipart",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
    assert Evidence.all_objects.filter(tenant=tenant).count() == 0


@patch("core.views.put_file")
def test_text_evidence_extracts_typed_attributes_and_quality(put_file):
    tenant, assessment, token = evidence_setup()
    with tenant_context(tenant.id):
        TenantEntitlement.objects.create(
            tenant=tenant,
            code="evidence_quality",
            configuration={"threshold": 5, "version": "tenant-profile-1"},
        )
    content = b"""Issue Date: 2026-01-01
Effective Date: 2026-01-02
Review Date: 2026-07-01
Approved By: CISO
Signed by CISO
Scope: Payments API, Mumbai
Period Covered: 2026-01-01 to 2026-12-31
Password Minimum Length: 12
"""
    response = APIClient().post(
        "/api/v1/evidence/uploads/",
        {
            "assessment": str(assessment.id),
            "title": "Access control policy",
            "source": "manual upload",
            "evidence_date": date.today().isoformat(),
            "classification": "confidential",
            "file": SimpleUploadedFile("policy.txt", content, content_type="text/plain"),
        },
        format="multipart",
        HTTP_AUTHORIZATION=f"Bearer {token}",
    )
    assert response.status_code == 201, response.data
    attributes = response.data["extracted_attributes"]
    assert attributes["effective_date"] == "2026-01-02"
    assert attributes["approver_name"] == "CISO"
    assert attributes["signature_present"] is True
    assert attributes["systems_covered"] == ["Payments API", "Mumbai"]
    assert attributes["period_covered_to"] == "2026-12-31"
    assert attributes["control_parameters"] == {"password_minimum_length": 12}
    provenance = response.data["extraction_provenance"]
    assert provenance["extractor_version"] == "native-text-1.0"
    assert provenance["truncated"] is False
    assert provenance["unsupported_media_type"] is False
    assert provenance["references"]["effective_date"] == {"line": 2}
    assert provenance["references"]["scope_statement"] == {"line": 6}
    assert response.data["quality_score"] == "4.50"
    assert response.data["quality_threshold"] == "5.00"
    assert response.data["quality_passed"] is False
    assert response.data["quality_profile_version"] == "tenant-profile-1"
    assert response.data["quality_breakdown"]["corroboration"] == 0
    assert AuditEvent.all_objects.filter(tenant=tenant, action="evidence.extracted").count() == 1
    assert AuditEvent.all_objects.filter(tenant=tenant, action="evidence.quality_scored").count() == 1
    put_file.assert_called_once()
