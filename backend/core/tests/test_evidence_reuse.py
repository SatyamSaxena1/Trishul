from datetime import date

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from core.evidence_reuse import evaluate_evidence
from core.models import (
    Assessment,
    AssessmentEvidence,
    AssessmentResponse,
    AuditorVerdict,
    ComplianceGap,
    ControlEvidenceLink,
    Evidence,
    EvidenceQualityOverride,
    EvidenceRequirement,
    EvidenceReuseEvaluation,
    FrameworkControlMapping,
    FrameworkVersion,
    Membership,
    OrganisationControl,
    PostClosureEvidenceChange,
    Requirement,
    Task,
    Tenant,
    UnifiedControlObjective,
)
from core.tenancy import tenant_context
from core.tests.test_security import make_application

pytestmark = pytest.mark.django_db


def test_shared_control_reuse_creates_precise_idempotent_gap_then_closes_it():
    tenant = Tenant.objects.create(slug="reuse-demo", name="Reuse demo")
    application = make_application(tenant, "Payments")
    with tenant_context(tenant.id):
        frameworks = [
            FrameworkVersion.objects.create(
                tenant=tenant,
                framework=name,
                version_name="Demo 1.0",
                source_url="https://example.test/demo",
                catalog_hash=character * 64,
            )
            for name, character in (("ISO-like demo", "a"), ("PCI-like demo", "b"))
        ]
        requirements = [
            Requirement.objects.create(
                tenant=tenant,
                framework_version=framework,
                control_id=control_id,
                title="Demonstration password requirement",
                requirement="Demonstration content; not licensed framework text.",
            )
            for framework, control_id in zip(frameworks, ("DEMO-ISO-1", "DEMO-PCI-1"), strict=True)
        ]
        uco = UnifiedControlObjective.objects.create(
            tenant=tenant,
            code="UCO-DEMO-PASSWORD",
            domain="Access control",
            objective="Enforce an approved minimum password length.",
            control_type="preventive",
            nature="technical",
        )
        mappings = [
            FrameworkControlMapping.objects.create(
                tenant=tenant,
                requirement=requirements[0],
                unified_control=uco,
                coverage="full",
                rationale="Demonstration mapping; expert verification pending.",
            ),
            FrameworkControlMapping.objects.create(
                tenant=tenant,
                requirement=requirements[1],
                unified_control=uco,
                coverage="partial",
                delta_condition={"attribute": "password_minimum_length", "operator": ">=", "value": 12},
                rationale="Demonstration stronger-password delta; expert verification pending.",
            ),
        ]
        EvidenceRequirement.objects.create(
            tenant=tenant,
            unified_control=uco,
            artefact_type="approved policy",
            required_attributes=["password_minimum_length", "effective_date"],
            validity_period_days=365,
            acceptance_criteria={"approved": True},
        )
        assessments = [
            Assessment.objects.create(
                tenant=tenant,
                application=application,
                framework_version=framework,
                name=framework.framework,
                audit_period_start=date(2026, 1, 1),
                audit_period_end=date(2026, 12, 31),
                scope={"systems": ["Payments API"]},
            )
            for framework in frameworks
        ]
        response = AssessmentResponse.objects.create(
            tenant=tenant, assessment=assessments[0], requirement=requirements[0]
        )
        control = OrganisationControl.objects.create(tenant=tenant, application=application, unified_control=uco)
        evidence = Evidence.objects.create(
            tenant=tenant,
            assessment=assessments[0],
            title="Password policy",
            source="local demo",
            evidence_date=date(2026, 2, 1),
            object_key=f"{tenant.id}/evidence/password-v1.txt",
            sha256="c" * 64,
            classification="internal",
            extracted_attributes={
                "effective_date": "2026-02-01",
                "period_covered_from": "2026-01-01",
                "period_covered_to": "2026-12-31",
                "systems_covered": ["Payments API"],
                "control_parameters": {"password_minimum_length": 8},
            },
            extraction_confidence="0.95",
            quality_score="4.00",
            quality_threshold="2.50",
            quality_passed=True,
        )
        AssessmentEvidence.objects.create(tenant=tenant, response=response, evidence=evidence)

        first = evaluate_evidence(evidence, actor_type="system", actor_id="reuse-test")
        evaluate_evidence(evidence, actor_type="system", actor_id="reuse-test")

        assert [item.outcome for item in first] == ["accept", "partial"]
        delta = next(item for item in first[1].checks if item["check"] == "delta_condition")
        assert delta | {"reason": None} == {
            "check": "delta_condition",
            "status": "FAIL",
            "attribute": "password_minimum_length",
            "actual": 8,
            "operator": ">=",
            "required": 12,
            "reason": None,
        }
        assert "target requires >= 12" in delta["reason"]
        assert EvidenceReuseEvaluation.objects.count() == 4
        assert ControlEvidenceLink.objects.count() == 4
        assert ComplianceGap.objects.count() == 1
        gap = ComplianceGap.objects.get()
        assert gap.failed_check == "delta_condition"
        assert gap.owner is None
        assert gap.details["check"]["actual"] == 8
        assert gap.details["check"]["required"] == 12
        assert gap.corrective_action == (
            "Update and approve replacement evidence containing password_minimum_length >= 12."
        )
        assert Task.objects.filter(gap=gap, status=Task.Status.OPEN).count() == 1

        replacement = Evidence.objects.create(
            tenant=tenant,
            assessment=evidence.assessment,
            title=evidence.title,
            source=evidence.source,
            evidence_date=evidence.evidence_date,
            object_key=f"{tenant.id}/evidence/password-v2.txt",
            sha256="d" * 64,
            classification=evidence.classification,
            extracted_attributes=evidence.extracted_attributes
            | {"control_parameters": {"password_minimum_length": 12}},
            extraction_confidence=evidence.extraction_confidence,
            quality_score=evidence.quality_score,
            quality_threshold=evidence.quality_threshold,
            quality_passed=True,
            evidence_version=2,
            supersedes=evidence,
        )
        AssessmentEvidence.objects.create(tenant=tenant, response=response, evidence=replacement)
        results = evaluate_evidence(replacement, actor_type="system", actor_id="reuse-test")

        assert [item.outcome for item in results] == ["accept", "accept"]
        gap.refresh_from_db()
        assert gap.status == "closed"
        assert Task.objects.get(gap=gap).status == Task.Status.COMPLETED
        assert mappings[1].coverage == "partial"
        assert control.reuse_evaluations.count() == 6

        auditor = get_user_model().objects.create(username="locking-auditor")
        verdict = AuditorVerdict.objects.create(
            tenant=tenant,
            engagement_id="00000000-0000-0000-0000-000000000001",
            organisation_control=control,
            decision=AuditorVerdict.Decision.COMPLIANT,
            rationale="Reviewed independently.",
            finalized_by=auditor,
        )
        third = Evidence.objects.create(
            tenant=tenant,
            assessment=evidence.assessment,
            title=evidence.title,
            source=evidence.source,
            evidence_date=evidence.evidence_date,
            object_key=f"{tenant.id}/evidence/password-v3.txt",
            sha256="e" * 64,
            classification=evidence.classification,
            extracted_attributes=replacement.extracted_attributes,
            extraction_confidence=replacement.extraction_confidence,
            quality_score=replacement.quality_score,
            quality_threshold=replacement.quality_threshold,
            quality_passed=True,
            evidence_version=3,
            supersedes=replacement,
        )
        AssessmentEvidence.objects.create(tenant=tenant, response=response, evidence=third)
        link_count = ControlEvidenceLink.objects.count()
        evaluate_evidence(third, actor_type="system", actor_id="reuse-test")
        verdict.refresh_from_db()
        assert verdict.locked is True
        assert ControlEvidenceLink.objects.count() == link_count
        change = PostClosureEvidenceChange.objects.get(evidence=third, prior_verdict=verdict)
        assert change.status == "pending"
        AuditorVerdict.objects.create(
            tenant=tenant,
            engagement_id=verdict.engagement_id,
            organisation_control=control,
            decision=verdict.decision,
            rationale="Unlocked for replacement review.",
            finalized_by=auditor,
            locked=False,
            supersedes=verdict,
        )
        fourth = Evidence.objects.create(
            tenant=tenant,
            assessment=evidence.assessment,
            title=evidence.title,
            source=evidence.source,
            evidence_date=evidence.evidence_date,
            object_key=f"{tenant.id}/evidence/password-v4.txt",
            sha256="6" * 64,
            classification=evidence.classification,
            extracted_attributes=third.extracted_attributes,
            extraction_confidence=third.extraction_confidence,
            quality_score=third.quality_score,
            quality_threshold=third.quality_threshold,
            quality_passed=True,
            evidence_version=4,
            supersedes=third,
        )
        AssessmentEvidence.objects.create(tenant=tenant, response=response, evidence=fourth)
        evaluate_evidence(fourth, actor_type="system", actor_id="reuse-test")
        assert ControlEvidenceLink.objects.count() == link_count + 2


def test_quality_override_requires_authorized_human_and_justification():
    tenant = Tenant.objects.create(slug="override-demo", name="Override demo")
    application = make_application(tenant, "Payments")
    with tenant_context(tenant.id):
        framework = FrameworkVersion.objects.create(
            tenant=tenant,
            framework="Demo",
            version_name="1",
            source_url="https://example.test/demo",
            catalog_hash="f" * 64,
        )
        assessment = Assessment.objects.create(
            tenant=tenant, application=application, framework_version=framework, name="Demo"
        )
        evidence = Evidence.objects.create(
            tenant=tenant,
            assessment=assessment,
            title="Weak evidence",
            source="upload",
            evidence_date=date.today(),
            object_key=f"{tenant.id}/evidence/weak.txt",
            sha256="1" * 64,
            classification="internal",
            quality_score="1.00",
            quality_threshold="2.50",
            quality_passed=False,
        )
    unauthorized = get_user_model().objects.create(username="override-owner")
    authorized = get_user_model().objects.create(username="override-manager")
    Membership.all_objects.create(tenant=tenant, user=unauthorized, role=Membership.Role.CONTROL_OWNER)
    Membership.all_objects.create(tenant=tenant, user=authorized, role=Membership.Role.COMPLIANCE_MANAGER)
    url = f"/api/v1/evidence/{evidence.id}/quality-overrides/"

    client = APIClient()
    client.force_authenticate(unauthorized)
    assert client.post(url, {"justification": "Reviewed manually."}, format="json").status_code == 403
    client.force_authenticate(authorized)
    assert client.post(url, {"justification": ""}, format="json").status_code == 400
    created = client.post(url, {"justification": "Signed original reviewed manually."}, format="json")

    assert created.status_code == 201, created.data
    override = EvidenceQualityOverride.all_objects.get(pk=created.data["id"])
    assert override.original_score == evidence.quality_score
    assert override.configured_threshold == evidence.quality_threshold
    assert override.authorized_by == authorized
    evidence.refresh_from_db()
    assert evidence.quality_passed is False
