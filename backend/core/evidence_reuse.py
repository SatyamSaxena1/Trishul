import hashlib
import operator
from datetime import date, timedelta
from decimal import Decimal

from django.db import models, transaction
from django.utils import timezone

from .models import (
    Assessment,
    AssessmentEvidence,
    AuditEvent,
    AuditorVerdict,
    ComplianceGap,
    ControlEvidenceLink,
    Evidence,
    EvidenceRequirement,
    EvidenceReuseEvaluation,
    FrameworkControlMapping,
    OrganisationControl,
    PostClosureEvidenceChange,
    Task,
)

ENGINE_VERSION = "deterministic-reuse-1.0"
OPERATORS = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
    "!=": operator.ne,
}


def _check(name, status, reason, **detail):
    return {"check": name, "status": status, "reason": reason, **detail}


def _lineage_root(evidence):
    while evidence.supersedes_id:
        evidence = Evidence.objects.get(pk=evidence.supersedes_id)
    return evidence.id


def _attribute(attributes, name):
    return attributes.get(name, attributes.get("control_parameters", {}).get(name))


def _evaluate(evidence, control, mapping, target_assessment):
    attributes = evidence.extracted_attributes
    requirements = list(EvidenceRequirement.objects.filter(unified_control=control.unified_control))
    checks = [_check("mapping_coverage", "PASS", f"Mapping coverage is {mapping.coverage}.", actual=mapping.coverage)]

    validity_days = min((item.validity_period_days for item in requirements if item.validity_period_days), default=None)
    effective = attributes.get("effective_date")
    try:
        effective_date = date.fromisoformat(effective) if effective else evidence.evidence_date
    except ValueError:
        effective_date = evidence.evidence_date
    stale = bool(validity_days and (timezone.localdate() - effective_date).days > validity_days)
    checks.append(
        _check(
            "freshness",
            "FAIL" if stale else "PASS",
            f"Evidence dated {effective_date} exceeds the {validity_days}-day validity window."
            if stale
            else "Evidence is within the configured validity window.",
            actual=effective_date.isoformat(),
            required_days=validity_days,
        )
    )

    period_failed = False
    if target_assessment and target_assessment.audit_period_start and target_assessment.audit_period_end:
        try:
            period_start = date.fromisoformat(attributes.get("period_covered_from", ""))
            period_end = date.fromisoformat(attributes.get("period_covered_to", ""))
            period_failed = (
                period_start > target_assessment.audit_period_start or period_end < target_assessment.audit_period_end
            )
        except ValueError:
            period_failed = True
        checks.append(
            _check(
                "audit_period",
                "FAIL" if period_failed else "PASS",
                "Evidence does not cover the required audit period."
                if period_failed
                else "Evidence covers the required audit period.",
                actual={
                    "from": attributes.get("period_covered_from"),
                    "to": attributes.get("period_covered_to"),
                },
                required={
                    "from": target_assessment.audit_period_start.isoformat(),
                    "to": target_assessment.audit_period_end.isoformat(),
                },
            )
        )
    else:
        checks.append(_check("audit_period", "PASS", "No target audit period is configured."))

    scope_missing = {}
    target_scope = target_assessment.scope if target_assessment else {}
    for kind in ("entities", "locations", "systems"):
        required = set(target_scope.get(kind, []))
        covered = set(attributes.get(f"{kind}_covered", []))
        if required - covered:
            scope_missing[kind] = sorted(required - covered)
    checks.append(
        _check(
            "scope_coverage",
            "FAIL" if scope_missing else "PASS",
            f"Evidence is missing required scope: {scope_missing}."
            if scope_missing
            else "Evidence covers configured scope.",
            actual={kind: attributes.get(f"{kind}_covered", []) for kind in ("entities", "locations", "systems")},
            required=target_scope,
            missing=scope_missing,
        )
    )

    required_attributes = sorted(
        {
            item.get("name") if isinstance(item, dict) else item
            for requirement in requirements
            for item in requirement.required_attributes
        }
        - {None}
    )
    missing_attributes = [name for name in required_attributes if _attribute(attributes, name) in (None, "", [])]
    checks.append(
        _check(
            "required_attributes",
            "FAIL" if missing_attributes else "PASS",
            f"Missing required attributes: {', '.join(missing_attributes)}."
            if missing_attributes
            else "All required attributes are present.",
            required=required_attributes,
            missing=missing_attributes,
        )
    )

    delta_failed = False
    if mapping.delta_condition:
        condition = mapping.delta_condition
        actual = _attribute(attributes, condition["attribute"])
        comparison = OPERATORS.get(condition["operator"])
        try:
            delta_failed = actual is None or comparison is None or not comparison(actual, condition["value"])
        except TypeError:
            delta_failed = True
        checks.append(
            _check(
                "delta_condition",
                "FAIL" if delta_failed else "PASS",
                f"{condition['attribute']} is {actual}; target requires {condition['operator']} {condition['value']}."
                if delta_failed
                else f"{condition['attribute']} satisfies the target delta.",
                attribute=condition["attribute"],
                actual=actual,
                operator=condition["operator"],
                required=condition["value"],
            )
        )
    else:
        checks.append(_check("delta_condition", "PASS", "No mapping delta applies."))

    override = evidence.quality_overrides.order_by("-authorized_at").first()
    checks.append(
        _check(
            "quality_threshold",
            "PASS" if evidence.quality_passed or override else "FAIL",
            f"Evidence quality is {evidence.quality_score}; threshold is {evidence.quality_threshold}."
            + (" A justified human override authorizes progression." if override else ""),
            actual=str(evidence.quality_score),
            required=str(evidence.quality_threshold),
            override_id=str(override.id) if override else None,
        )
    )
    duplicate = Evidence.objects.filter(sha256=evidence.sha256).exclude(pk=evidence.pk).exists()
    checks.append(
        _check(
            "duplicate",
            "FAIL" if duplicate else "PASS",
            "Duplicate content exists." if duplicate else "No duplicate content exists.",
        )
    )

    if duplicate:
        outcome = EvidenceReuseEvaluation.Outcome.DUPLICATE
    elif stale:
        outcome = EvidenceReuseEvaluation.Outcome.REJECT_STALE
    elif period_failed or scope_missing:
        outcome = EvidenceReuseEvaluation.Outcome.REJECT_OUT_OF_SCOPE
    elif missing_attributes or mapping.coverage == FrameworkControlMapping.Coverage.NONE:
        outcome = EvidenceReuseEvaluation.Outcome.REJECT_INSUFFICIENT
    elif not evidence.quality_passed and not override:
        outcome = EvidenceReuseEvaluation.Outcome.REJECT_LOW_QUALITY
    elif delta_failed:
        outcome = EvidenceReuseEvaluation.Outcome.PARTIAL
    elif evidence.extraction_confidence < Decimal("0.85"):
        outcome = EvidenceReuseEvaluation.Outcome.ACCEPT_REVIEW_SUGGESTED
    else:
        outcome = EvidenceReuseEvaluation.Outcome.ACCEPT
    return outcome, checks


def _corrective(check):
    if check["check"] == "delta_condition":
        return (
            f"Update and approve replacement evidence containing {check['attribute']} "
            f"{check['operator']} {check['required']}."
        )
    if check["check"] == "required_attributes":
        return f"Upload approved replacement evidence containing: {', '.join(check['missing'])}."
    if check["check"] == "freshness":
        return f"Upload a dated replacement within the {check['required_days']}-day validity window."
    if check["check"] == "scope_coverage":
        return f"Upload evidence covering the missing scope: {check['missing']}."
    if check["check"] == "audit_period":
        return f"Upload evidence covering {check['required']['from']} through {check['required']['to']}."
    return "Provide replacement evidence that passes the evidence-quality threshold."


def _sync_gaps(evaluation, actor_type, actor_id):
    evidence = evaluation.evidence
    root = _lineage_root(evidence)
    failed = {
        item["check"]: item for item in evaluation.checks if item["status"] == "FAIL" and item["check"] != "duplicate"
    }
    owner = evaluation.organisation_control.owner
    if not owner:
        assignment = evaluation.organisation_control.assignments.filter(is_active=True).order_by("created_at").first()
        owner = assignment.assignee if assignment else None
    for check_name in (
        "freshness",
        "audit_period",
        "scope_coverage",
        "required_attributes",
        "delta_condition",
        "quality_threshold",
    ):
        fingerprint = hashlib.sha256(
            f"{root}:{evaluation.organisation_control_id}:{evaluation.requirement_id}:{check_name}".encode()
        ).hexdigest()
        check = failed.get(check_name)
        gap = ComplianceGap.objects.filter(source_fingerprint=fingerprint).first()
        if check:
            corrective = _corrective(check)
            details = {
                "evidence_lineage": str(root),
                "evidence_version": evidence.evidence_version,
                "evaluation_id": str(evaluation.id),
                "check": check,
            }
            if gap:
                ComplianceGap.objects.filter(pk=gap.pk).update(
                    evidence=evidence,
                    description=check["reason"],
                    corrective_action=corrective,
                    details=details,
                    status="open",
                    closed_at=None,
                    version=gap.version + 1,
                )
                gap.refresh_from_db()
            else:
                gap = ComplianceGap.objects.create(
                    tenant=evaluation.tenant,
                    organisation_control=evaluation.organisation_control,
                    evidence=evidence,
                    requirement=evaluation.requirement,
                    failed_check=check_name,
                    description=check["reason"],
                    corrective_action=corrective,
                    details=details,
                    owner=owner,
                    due_at=timezone.now() + timedelta(days=14),
                    source_fingerprint=fingerprint,
                )
                AuditEvent.append(
                    tenant=evaluation.tenant,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action="evidence_gap.created",
                    resource_type="core.compliancegap",
                    resource_id=gap.id,
                    details={"evaluation_id": str(evaluation.id), "failed_check": check_name},
                )
            task, created = Task.objects.get_or_create(
                tenant=evaluation.tenant,
                task_type="evidence_reupload",
                source_type="compliance_gap",
                source_id=gap.id,
                defaults={
                    "title": f"Replace evidence for {evaluation.requirement.control_id}",
                    "description": corrective,
                    "priority": "high",
                    "owner": owner,
                    "organisation_control": evaluation.organisation_control,
                    "gap": gap,
                    "due_at": gap.due_at,
                },
            )
            if not created and task.status == Task.Status.COMPLETED:
                Task.objects.filter(pk=task.pk).update(status=Task.Status.OPEN, version=task.version + 1)
        elif gap and gap.status == "open":
            ComplianceGap.objects.filter(pk=gap.pk).update(
                status="closed", closed_at=timezone.now(), version=gap.version + 1
            )
            Task.objects.filter(gap=gap).update(status=Task.Status.COMPLETED, version=models.F("version") + 1)
            AuditEvent.append(
                tenant=evaluation.tenant,
                actor_type=actor_type,
                actor_id=actor_id,
                action="evidence_gap.closed",
                resource_type="core.compliancegap",
                resource_id=gap.id,
                details={"evaluation_id": str(evaluation.id)},
            )


@transaction.atomic
def evaluate_evidence(evidence, *, actor_type, actor_id):
    source_requirement_ids = AssessmentEvidence.objects.filter(evidence=evidence).values_list(
        "response__requirement_id", flat=True
    )
    source_uco_ids = FrameworkControlMapping.objects.filter(requirement_id__in=source_requirement_ids).values_list(
        "unified_control_id", flat=True
    )
    mappings = FrameworkControlMapping.objects.filter(unified_control_id__in=source_uco_ids).select_related(
        "requirement__framework_version", "unified_control"
    )
    controls = {
        item.unified_control_id: item
        for item in OrganisationControl.objects.filter(
            application=evidence.assessment.application, unified_control_id__in=source_uco_ids
        ).select_related("unified_control", "owner")
    }
    results = []
    for mapping in mappings:
        control = controls.get(mapping.unified_control_id)
        if not control:
            continue
        target_assessment = Assessment.objects.filter(
            application=control.application, framework_version=mapping.requirement.framework_version
        ).first()
        outcome, checks = _evaluate(evidence, control, mapping, target_assessment)
        reasons = [item["reason"] for item in checks if item["status"] == "FAIL"]
        evaluation = EvidenceReuseEvaluation.objects.create(
            tenant=evidence.tenant,
            evidence=evidence,
            organisation_control=control,
            requirement=mapping.requirement,
            unified_control=mapping.unified_control,
            mapping=mapping,
            mapping_coverage=mapping.coverage,
            outcome=outcome,
            checks=checks,
            reasons=reasons,
            engine_version=ENGINE_VERSION,
            confidence=min(evidence.extraction_confidence, mapping.confidence),
        )
        latest_verdict = AuditorVerdict.objects.filter(organisation_control=control).order_by("-finalized_at").first()
        if latest_verdict and latest_verdict.locked and evidence.supersedes_id:
            PostClosureEvidenceChange.objects.get_or_create(
                tenant=evidence.tenant,
                organisation_control=control,
                evidence=evidence,
                prior_verdict=latest_verdict,
                defaults={"evaluation": evaluation},
            )
            AuditEvent.append(
                tenant=evidence.tenant,
                actor_type=actor_type,
                actor_id=actor_id,
                action="evidence.changed_after_closure",
                resource_type="core.organisationcontrol",
                resource_id=control.id,
                details={"evidence_id": str(evidence.id), "verdict_id": str(latest_verdict.id)},
            )
            results.append(evaluation)
            continue
        if outcome in {
            EvidenceReuseEvaluation.Outcome.ACCEPT,
            EvidenceReuseEvaluation.Outcome.ACCEPT_REVIEW_SUGGESTED,
            EvidenceReuseEvaluation.Outcome.PARTIAL,
        }:
            ControlEvidenceLink.objects.create(
                tenant=evidence.tenant,
                organisation_control=control,
                evidence=evidence,
                source_type="reuse_evaluation",
                source_id=evaluation.id,
                source_hash=evidence.sha256,
                verdict=outcome,
                confidence=round(float(evaluation.confidence) * 5),
                reason="; ".join(reasons) or "All deterministic checks passed.",
                mapping_version=str(mapping.version),
                system_generated=True,
            )
        _sync_gaps(evaluation, actor_type, actor_id)
        AuditEvent.append(
            tenant=evidence.tenant,
            actor_type=actor_type,
            actor_id=actor_id,
            action="evidence.reuse_evaluated",
            resource_type="core.evidencereuseevaluation",
            resource_id=evaluation.id,
            details={"outcome": outcome, "evidence_id": str(evidence.id)},
        )
        results.append(evaluation)
    return results
