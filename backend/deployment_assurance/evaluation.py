"""Evaluation orchestration: snapshot in, decision out.

The pipeline, and where each guarantee is established:

1. **Normalize** the untrusted artifact into the canonical envelope, under hard
   structural bounds, and hash the result.
2. **Evaluate** every registered rule against every resource, in sorted order,
   producing deterministic results.
3. **Score** each unwaived failure through the shared risk model.
4. **Decide** using blocker rules first and the aggregate score second.
5. **Record** the normalized snapshot, the result manifest and the decision
   envelope as immutable, hashed evidence.

A rule that raises is contained: its failure becomes an ``error`` result for the
resource it was examining, the run continues, and the run is marked as having
errored — which fails the gate closed on protected targets. One defective rule
must not be able to silently approve a deployment, nor to take down the gate.
"""

import logging
from decimal import Decimal

from django.db import transaction
from django.utils import timezone

from core.models import AuditEvent
from core.risk import FORMULA_VERSION
from core.runner import normalize_deployment

from . import decisions, evidence, grc
from .limits import (
    MAX_NORMALIZED_BYTES,
    MAX_RESULT_MANIFEST_BYTES,
    MAX_RESULTS,
    ArtifactTooLarge,
    UnsafeArtifact,
)
from .models import (
    ControlResult,
    DeploymentDecision,
    DeploymentSnapshot,
    EvaluationRun,
    EvidenceArtifact,
    ExceptionWaiver,
    Outcome,
    PolicyRule,
)
from .normalizers import NORMALIZER_VERSION
from .policy import ENGINE_VERSION, REGISTRY
from .policy.sdk import RuleContext, TargetFacts, result_fingerprint
from .resources import canonical_json, load_resources, sha256_hex

logger = logging.getLogger(__name__)


class EvaluationError(RuntimeError):
    """The run could not be completed. The gate fails closed."""


def _target_facts(target) -> TargetFacts:
    return TargetFacts(
        environment=target.environment,
        provider=target.provider,
        criticality=target.criticality,
        data_sensitivity=target.data_sensitivity,
        internet_exposed=target.internet_exposed,
        is_production=target.is_protected,
    )


def _resolved_parameters(rule, *, profile_parameters, run_parameters) -> dict:
    """Merge parameters, most specific last.

    Rule defaults < policy-profile overrides < per-run overrides. The merged
    result is recorded on the run so a verdict can be reproduced exactly.
    """
    merged = dict(rule.default_parameters)
    merged.update((profile_parameters or {}).get(rule.rule_id, {}))
    merged.update((run_parameters or {}).get(rule.rule_id, {}))
    return merged


def evaluate_snapshot(run: EvaluationRun) -> DeploymentDecision:
    """Execute one evaluation run to completion and return its decision."""
    tenant = run.tenant
    target = run.target
    snapshot = run.snapshot
    stored_rules = {
        rule.stable_key: rule
        for rule in PolicyRule.all_objects.filter(tenant=tenant, policy_pack=run.policy_pack, active=True)
    }
    excluded = set((run.policy_profile.excluded_rule_keys if run.policy_profile else []) or [])
    profile_parameters = (run.policy_profile.parameters if run.policy_profile else {}) or {}

    # --- 1. Normalize -----------------------------------------------------
    _transition(run, EvaluationRun.State.NORMALIZING)
    try:
        document = normalize_deployment(snapshot=snapshot, run_id=run.id)
    except (UnsafeArtifact, ArtifactTooLarge) as exc:
        raise EvaluationError(f"artifact_rejected:{type(exc).__name__}") from exc

    normalized_bytes = canonical_json(document)
    if len(normalized_bytes) > MAX_NORMALIZED_BYTES:
        raise EvaluationError("normalized_snapshot_too_large")
    normalized_digest = sha256_hex(normalized_bytes)
    resources = load_resources(document)

    normalized_evidence = evidence.record(
        tenant=tenant,
        target=target,
        snapshot=snapshot,
        evaluation_run=run,
        role=EvidenceArtifact.Role.NORMALIZED_SNAPSHOT,
        payload=normalized_bytes,
        media_type="application/json",
        source={
            "type": "normalizer",
            "source_type": snapshot.source_type,
            "artifact_sha256": snapshot.artifact_sha256,
            "normalizer_version": NORMALIZER_VERSION,
        },
        policy_pack_hash=run.policy_pack.content_hash,
    )
    DeploymentSnapshot.all_objects.filter(pk=snapshot.pk).update(
        normalized_object_key=normalized_evidence.object_key,
        normalized_sha256=normalized_digest,
        resource_count=len(resources),
    )

    run.input_hash = sha256_hex(
        canonical_json(
            {
                "artifact_sha256": snapshot.artifact_sha256,
                "normalized_sha256": normalized_digest,
                "parameters": run.parameters,
            }
        )
    )
    run.policy_hash = run.policy_pack.content_hash
    run.engine_versions = {
        "engine": ENGINE_VERSION,
        "normalizer": NORMALIZER_VERSION,
        "scoring": decisions.SCORING_VERSION,
        "risk_formula": FORMULA_VERSION,
    }

    # --- 2. Evaluate ------------------------------------------------------
    _transition(run, EvaluationRun.State.EVALUATING)
    had_error = False
    emitted: list[dict] = []
    covered_types = REGISTRY.covered_resource_types
    unevaluated_types: dict[str, int] = {}

    for resource in resources:
        if resource.resource_type not in covered_types:
            # No rule claims this type. Recorded explicitly — an unrecognised
            # resource is never treated as a pass.
            unevaluated_types[resource.resource_type] = unevaluated_types.get(resource.resource_type, 0) + 1
            continue
        for rule in REGISTRY:
            stored = stored_rules.get(rule.rule_id)
            if stored is None or rule.rule_id in excluded:
                continue
            context = RuleContext(
                target=_target_facts(target),
                parameters=_resolved_parameters(
                    rule, profile_parameters=profile_parameters, run_parameters=run.parameters
                ),
                policy_version=f"{run.policy_pack.key}@{run.policy_pack.pack_version}",
            )
            try:
                results = rule.evaluate(context, resource)
            except Exception as exc:  # noqa: BLE001 - one defective rule must not fail the whole run
                logger.exception("Rule %s failed on %s", rule.rule_id, resource.resource_id)
                had_error = True
                emitted.append(
                    _row(
                        rule=rule,
                        stored=stored,
                        resource=resource,
                        outcome=Outcome.ERROR,
                        reason_code="RULE_EXECUTION_FAILED",
                        # Type name only: an exception message can carry
                        # fragments of the untrusted artifact.
                        rationale=f"The rule raised {type(exc).__name__} and produced no verdict.",
                        severity=stored.severity,
                        confidence=0,
                    )
                )
                continue
            for result in results:
                emitted.append(
                    _row(
                        rule=rule,
                        stored=stored,
                        resource=resource,
                        outcome=result.outcome,
                        reason_code=result.reason_code,
                        rationale=result.rationale,
                        severity=result.severity if result.severity is not None else stored.severity,
                        confidence=result.confidence,
                        observed=result.observed,
                        expected=result.expected,
                    )
                )
            if len(emitted) > MAX_RESULTS:
                raise EvaluationError("result_volume_exceeded")

    # --- 3. Persist results, apply waivers, score -------------------------
    _transition(run, EvaluationRun.State.DECIDING)
    profile = decisions.TargetProfile.from_target(target)
    waivers = list(
        ExceptionWaiver.all_objects.filter(
            tenant=tenant, target=target, status=ExceptionWaiver.Status.APPROVED, expires_at__gt=timezone.now()
        ).select_related("policy_rule")
    )
    waiver_index = {
        (waiver.policy_rule_id, waiver.rule_version, waiver.resource_fingerprint): waiver for waiver in waivers
    }

    stored_results: list[ControlResult] = []
    residuals: list[Decimal] = []
    seen_fingerprints: set[str] = set()
    for row in emitted:
        if row["fingerprint"] in seen_fingerprints:
            # Two rules cannot collide (the rule id is in the fingerprint), so
            # this only happens if a rule emits the same reason twice for one
            # resource. Keep the first; the constraint would reject the second.
            continue
        seen_fingerprints.add(row["fingerprint"])
        stored_rule = row.pop("_stored")
        category = row.pop("_category")
        waiver = waiver_index.get((stored_rule.id, stored_rule.rule_version, row["fingerprint"]))
        result = ControlResult.all_objects.create(
            tenant=tenant,
            evaluation_run=run,
            policy_rule=stored_rule,
            waived_by=waiver if row["outcome"] == Outcome.FAIL else None,
            **row,
        )
        stored_results.append(result)
        if result.outcome in decisions.CONTRIBUTING_OUTCOMES and result.waived_by_id is None:
            _, score = decisions.score_result(profile=profile, result=result, rule_category=category)
            result.residual_risk = score.residual
            ControlResult.all_objects.filter(pk=result.pk).update(residual_risk=score.residual)
            if result.outcome == Outcome.FAIL:
                residuals.append(score.priority)

    risk_total = decisions.deployment_risk(residuals)
    thresholds = _thresholds(run)
    outcome = decisions.decide(
        profile=profile,
        results=stored_results,
        thresholds=thresholds,
        risk_total=risk_total,
        had_error=had_error,
    )

    # --- 4. Record evidence and finalize ----------------------------------
    # Split deliberately: `results` carries only run-independent content, so its
    # digest is byte-identical across two evaluations of the same snapshot under
    # the same pack. The run identifier lives outside that digest — otherwise
    # every re-run would look like a different outcome, and reproducibility
    # would be unprovable.
    result_rows = [
        {
            "rule_id": result.policy_rule.stable_key,
            "rule_version": result.policy_rule.rule_version,
            "resource_type": result.resource_type,
            "resource_id": result.resource_id,
            "outcome": result.outcome,
            "reason_code": result.reason_code,
            "severity": result.severity,
            "fingerprint": result.fingerprint,
            "waived": result.waived_by_id is not None,
        }
        for result in stored_results
    ]
    results_hash = sha256_hex(
        canonical_json(
            {
                "input_hash": run.input_hash,
                "policy_hash": run.policy_hash,
                "engine_versions": run.engine_versions,
                "unevaluated_resource_types": dict(sorted(unevaluated_types.items())),
                "results": result_rows,
            }
        )
    )
    manifest = {
        "schema_version": "trishul-result-manifest/1.1",
        "evaluation_run_id": str(run.id),
        "input_hash": run.input_hash,
        "policy_hash": run.policy_hash,
        "results_hash": results_hash,
        "engine_versions": run.engine_versions,
        "unevaluated_resource_types": dict(sorted(unevaluated_types.items())),
        "results": result_rows,
    }
    manifest_evidence = evidence.record_json(
        tenant=tenant,
        target=target,
        snapshot=snapshot,
        evaluation_run=run,
        role=EvidenceArtifact.Role.RESULT_MANIFEST,
        document=manifest,
        source={"type": "evaluator", "engine_version": ENGINE_VERSION},
        policy_pack_hash=run.policy_pack.content_hash,
        max_bytes=MAX_RESULT_MANIFEST_BYTES,
    )
    grc.synchronize(
        tenant=tenant,
        target=target,
        results=stored_results,
        manifest_evidence=manifest_evidence,
    )

    digest = decisions.decision_hash(run=run, outcome=outcome, thresholds=thresholds)
    decision = DeploymentDecision.all_objects.create(
        tenant=tenant,
        evaluation_run=run,
        target=target,
        threshold_profile=thresholds,
        decision=outcome.decision,
        compliance_score=outcome.compliance,
        risk_score=outcome.risk,
        reason_codes=outcome.reason_codes,
        counts={**outcome.counts, "unevaluated_resource_types": len(unevaluated_types)},
        decision_hash=digest,
    )
    evidence.record_json(
        tenant=tenant,
        target=target,
        snapshot=snapshot,
        evaluation_run=run,
        role=EvidenceArtifact.Role.DECISION_ENVELOPE,
        document={
            "schema_version": "trishul-decision-envelope/1.0",
            "decision": outcome.decision,
            "decision_hash": digest,
            "compliance_score": str(outcome.compliance),
            "risk_score": str(outcome.risk),
            "reason_codes": outcome.reason_codes,
            "blocking_fingerprints": outcome.blocking_fingerprints,
            "threshold_profile": f"{thresholds.name}@{thresholds.profile_version}",
            "result_manifest_sha256": manifest_evidence.sha256,
        },
        source={"type": "decision_service", "scoring_version": decisions.SCORING_VERSION},
        policy_pack_hash=run.policy_pack.content_hash,
    )

    run.result_manifest_key = manifest_evidence.object_key
    run.result_manifest_hash = manifest_evidence.sha256
    run.summary = {
        **outcome.counts,
        "resources": len(resources),
        "rules": len(stored_rules),
        "results_hash": results_hash,
    }
    run.state = EvaluationRun.State.COMPLETED
    run.completed_at = timezone.now()
    run.version += 1
    run.save(
        update_fields=[
            "input_hash",
            "policy_hash",
            "engine_versions",
            "result_manifest_key",
            "result_manifest_hash",
            "summary",
            "state",
            "completed_at",
            "version",
            "updated_at",
        ]
    )
    _supersede_previous(decision)

    AuditEvent.append(
        tenant=tenant,
        actor_type="system",
        actor_id="deployment-assurance",
        action="deployment.decision.recorded",
        resource_type="deployment_assurance.deploymentdecision",
        resource_id=decision.id,
        details={
            "target_id": str(target.id),
            "evaluation_run_id": str(run.id),
            "decision": decision.decision,
            "risk_score": str(decision.risk_score),
            "compliance_score": str(decision.compliance_score),
            "decision_hash": digest,
            "policy_pack": f"{run.policy_pack.key}@{run.policy_pack.pack_version}",
        },
    )
    return decision


def _row(
    *, rule, stored, resource, outcome, reason_code, rationale, severity, confidence, observed=None, expected=None
):
    return {
        "resource_type": resource.resource_type,
        "resource_id": resource.resource_id[:400],
        "resource_path": resource.source_path[:600],
        "outcome": outcome,
        "reason_code": reason_code,
        "severity": int(severity),
        "confidence": int(confidence),
        "rationale": rationale,
        "observed": dict(observed or {}),
        "expected": dict(expected or {}),
        "blocking": bool(stored.blocking),
        "fingerprint": result_fingerprint(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            reason_code=reason_code,
        ),
        "_stored": stored,
        "_category": stored.category,
    }


def _thresholds(run: EvaluationRun):
    if run.policy_profile:
        return run.policy_profile.threshold_profile
    from .models import DecisionThresholdProfile

    profile = DecisionThresholdProfile.all_objects.filter(tenant=run.tenant, is_default=True).first()
    if profile is None:
        raise EvaluationError("no_threshold_profile_configured")
    return profile


def _supersede_previous(decision: DeploymentDecision) -> None:
    """Point the target's previous open decision at its successor."""
    DeploymentDecision.all_objects.filter(
        tenant=decision.tenant, target=decision.target, superseded_by__isnull=True
    ).exclude(pk=decision.pk).update(superseded_by=decision)


def _transition(run: EvaluationRun, state: str) -> None:
    with transaction.atomic():
        run.state = state
        run.version += 1
        run.save(update_fields=["state", "version", "updated_at"])
