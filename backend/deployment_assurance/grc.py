"""Bridge deterministic deployment results into the shared GRC lifecycle."""

from datetime import timedelta

from django.utils import timezone

from core.models import (
    AssessmentObservation,
    AuditorVerdict,
    ComplianceGap,
    ControlEvidenceLink,
    OrganisationControl,
    Remediation,
    Risk,
    RiskLink,
    RiskScore,
    Task,
)
from core.risk import FORMULA_VERSION

from .decisions import TargetProfile, score_result
from .models import ControlResult, Outcome
from .resources import canonical_json, sha256_hex

OPEN_OUTCOMES = frozenset({Outcome.FAIL, Outcome.MANUAL_REVIEW})


def synchronize(*, tenant, target, results, manifest_evidence):
    """Create or advance one stable gap→risk→task chain per rule/resource."""
    for result in results:
        unified_control = result.policy_rule.unified_control
        if unified_control is None:
            continue
        organisation_control, _ = OrganisationControl.all_objects.get_or_create(
            tenant=tenant,
            application=target.application,
            unified_control=unified_control,
        )
        ControlEvidenceLink.all_objects.get_or_create(
            tenant=tenant,
            organisation_control=organisation_control,
            source_type="deployment_assurance.controlresult",
            source_id=result.id,
            defaults={
                "source_hash": manifest_evidence.sha256,
                "verdict": result.outcome,
                "confidence": result.confidence,
                "reason": result.rationale,
                "mapping_version": f"{unified_control.code}@{unified_control.objective_version}",
                "system_generated": True,
            },
        )
        AssessmentObservation.all_objects.get_or_create(
            tenant=tenant,
            source_type="deployment_assurance.controlresult",
            source_id=result.id,
            defaults={
                "organisation_control": organisation_control,
                "title": result.policy_rule.title,
                "description": result.rationale,
                "outcome": result.outcome,
            },
        )
        issue_key = _issue_key(target, result)
        latest_verdict = (
            AuditorVerdict.all_objects.filter(tenant=tenant, organisation_control=organisation_control)
            .order_by("-finalized_at")
            .first()
        )
        locked = latest_verdict if latest_verdict and latest_verdict.locked else None
        if result.outcome in OPEN_OUTCOMES:
            gap, _ = ComplianceGap.all_objects.get_or_create(
                tenant=tenant,
                source_fingerprint=issue_key,
                defaults={
                    "organisation_control": organisation_control,
                    "description": result.rationale,
                    "corrective_action": result.policy_rule.remediation_guidance,
                },
            )
            risk = _risk_for_gap(tenant=tenant, target=target, result=result, gap=gap)
            remediation, _ = Remediation.all_objects.get_or_create(
                tenant=tenant,
                gap=gap,
                defaults={
                    "risk": risk,
                    "description": result.policy_rule.remediation_guidance,
                    "owner": organisation_control.owner,
                    "due_at": timezone.now() + timedelta(days=30),
                },
            )
            Task.all_objects.get_or_create(
                tenant=tenant,
                task_type="deployment_remediation",
                source_type="core.compliancegap",
                source_id=gap.id,
                defaults={
                    "title": f"Remediate {result.policy_rule.stable_key}: {result.policy_rule.title}"[:300],
                    "description": result.policy_rule.remediation_guidance,
                    "priority": "critical" if result.blocking or result.severity >= 5 else "high",
                    "owner": organisation_control.owner,
                    "organisation_control": organisation_control,
                    "gap": gap,
                    "risk": risk,
                    "due_at": remediation.due_at,
                },
            )
            ControlResult.all_objects.filter(pk=result.pk).update(gap=gap, risk=risk)
            if locked:
                _notify_locked_change(tenant, locked, organisation_control, gap, risk)
            elif organisation_control.status == OrganisationControl.Status.NOT_STARTED:
                OrganisationControl.all_objects.filter(pk=organisation_control.pk).update(
                    status=OrganisationControl.Status.EVIDENCE_SUBMITTED,
                    version=organisation_control.version + 1,
                )
        elif result.outcome == Outcome.PASS:
            gap = ComplianceGap.all_objects.filter(tenant=tenant, source_fingerprint=issue_key, status="open").first()
            if gap and locked:
                _notify_locked_change(tenant, locked, organisation_control, gap, None)
            elif gap:
                _close_gap(tenant, gap)
            if not locked:
                OrganisationControl.all_objects.filter(pk=organisation_control.pk).update(
                    status=OrganisationControl.Status.EVIDENCE_SUBMITTED,
                    version=organisation_control.version + 1,
                )


def _issue_key(target, result):
    return sha256_hex(
        canonical_json(
            {
                "target": str(target.id),
                "rule": result.policy_rule.stable_key,
                "rule_version": result.policy_rule.rule_version,
                "resource_type": result.resource_type,
                "resource_id": result.resource_id,
            }
        )
    )


def _risk_for_gap(*, tenant, target, result, gap):
    link = (
        RiskLink.all_objects.filter(
            tenant=tenant,
            relationship="derived_from_gap",
            source_type="core.compliancegap",
            source_id=gap.id,
        )
        .select_related("risk")
        .first()
    )
    if link:
        risk = link.risk
    else:
        risk = Risk.all_objects.create(
            tenant=tenant,
            application=target.application,
            title=f"[{result.policy_rule.stable_key}] {result.policy_rule.title}"[:300],
            description=result.rationale,
            state="open",
            owner=gap.organisation_control.owner,
        )
        RiskLink.all_objects.create(
            tenant=tenant,
            risk=risk,
            relationship="derived_from_gap",
            source_type="core.compliancegap",
            source_id=gap.id,
        )
    inputs, score = score_result(
        profile=TargetProfile.from_target(target), result=result, rule_category=result.policy_rule.category
    )
    RiskScore.all_objects.create(
        tenant=tenant,
        risk=risk,
        formula_version=FORMULA_VERSION,
        inputs=inputs,
        inherent=score.inherent,
        residual=score.residual,
        priority=score.priority,
    )
    return risk


def _close_gap(tenant, gap):
    now = timezone.now()
    ComplianceGap.all_objects.filter(pk=gap.pk).update(status="closed", closed_at=now, version=gap.version + 1)
    links = RiskLink.all_objects.filter(
        tenant=tenant,
        relationship="derived_from_gap",
        source_type="core.compliancegap",
        source_id=gap.id,
    )
    risk_ids = list(links.values_list("risk_id", flat=True))
    Risk.all_objects.filter(tenant=tenant, id__in=risk_ids).update(state="mitigated")
    Remediation.all_objects.filter(tenant=tenant, gap=gap).update(status="completed")
    Task.all_objects.filter(tenant=tenant, gap=gap, task_type="deployment_remediation").update(
        status=Task.Status.COMPLETED
    )


def _notify_locked_change(tenant, verdict, organisation_control, gap, risk):
    Task.all_objects.get_or_create(
        tenant=tenant,
        task_type="auditor_change_review",
        source_type="core.auditorverdict",
        source_id=verdict.id,
        defaults={
            "title": f"Evidence changed after auditor lock: {organisation_control.unified_control.code}"[:300],
            "description": "Deployment evidence changed after a final auditor verdict; unlock and review explicitly.",
            "priority": "high",
            "status": Task.Status.REVIEW,
            "owner": verdict.finalized_by,
            "organisation_control": organisation_control,
            "gap": gap,
            "risk": risk,
        },
    )
