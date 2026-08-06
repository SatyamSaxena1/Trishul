"""Risk derivation, compliance scoring and the gate decision.

The module deliberately reuses ``core.risk.calculate`` rather than inventing a
parallel score. A deployment finding and a code finding then sit on the same
scale, which is what makes the CISO view coherent — and it means the risk
formula stays versioned and audited in exactly one place.

Ordering matters and is not negotiable: **explicit blocker rules are evaluated
before the aggregate score.** A single critical failure must not be averaged
away by ninety passing controls. The numeric score only decides the cases the
blocker rules leave open.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Iterable, Sequence

from core.risk import FORMULA_VERSION, calculate

from .models import Decision, DeploymentTarget, Environment, Outcome
from .resources import ResourceType, canonical_json, sha256_hex

SCORING_VERSION = "1.0.0"

# How far a failure can spread, by resource type. Feeds the risk model's
# blast_radius input on the shared 0-5 scale.
BLAST_RADIUS = {
    ResourceType.IDENTITY_POLICY: 5,
    ResourceType.SECRET_MATERIAL: 5,
    ResourceType.OS_HOST: 4,
    ResourceType.DATABASE_INSTANCE: 4,
    ResourceType.STORAGE_BUCKET: 4,
    ResourceType.INGRESS_RULE: 3,
    ResourceType.CONTAINER: 3,
    ResourceType.COMPUTE_INSTANCE: 3,
    ResourceType.STORAGE_VOLUME: 3,
    ResourceType.VULNERABILITY: 3,
    ResourceType.TLS_ENDPOINT: 3,
    ResourceType.LOGGING_SINK: 2,
    ResourceType.BACKUP_PLAN: 2,
}

# Categories where a failure is directly reachable by an attacker rather than
# being a detective or recovery weakness.
DIRECTLY_EXPLOITABLE = frozenset({"network", "identity", "encryption", "vulnerability", "supply_chain"})

CONTRIBUTING_OUTCOMES = frozenset({Outcome.FAIL, Outcome.WARNING, Outcome.MANUAL_REVIEW})


def _clamp(value: int, low: int = 0, high: int = 5) -> int:
    return max(low, min(high, value))


@dataclass(frozen=True)
class TargetProfile:
    """The subset of target facts the scoring model consumes."""

    environment: str
    criticality: int
    data_sensitivity: int
    internet_exposed: bool

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @classmethod
    def from_target(cls, target: DeploymentTarget) -> "TargetProfile":
        return cls(
            environment=target.environment,
            criticality=target.criticality,
            data_sensitivity=target.data_sensitivity,
            internet_exposed=target.internet_exposed,
        )


def risk_inputs(*, profile: TargetProfile, result, rule_category: str, age_days: int = 0) -> dict:
    """Derive the shared risk-model inputs from one control result.

    Deterministic by construction: every input is a pure function of the result,
    the rule category and the target profile. The full dictionary is retained on
    the ``RiskScore`` row so a score can always be recomputed and explained.
    """
    severity = _clamp(int(result.severity))
    observed = result.observed if isinstance(result.observed, dict) else {}

    exploit_known = bool(observed.get("exploit_known"))
    directly_exploitable = rule_category in DIRECTLY_EXPLOITABLE

    if profile.internet_exposed:
        reachability, exposure = 5, 5
    elif profile.is_production:
        reachability, exposure = 4, 3
    else:
        reachability, exposure = 2, 2

    return {
        "exploitability": _clamp(severity if directly_exploitable else severity - 1),
        "reachability": reachability,
        "exposure": exposure,
        # A failure that is directly exploitable offers a shorter attack path
        # than one that merely weakens detection or recovery.
        "attack_path": _clamp(severity - (0 if directly_exploitable else 2)),
        "threat_relevance": 5 if exploit_known else _clamp(severity - 1),
        "confidence": _clamp(int(result.confidence)),
        "business_impact": _clamp(profile.criticality),
        "data_sensitivity": _clamp(profile.data_sensitivity),
        # Regulatory exposure tracks data sensitivity, raised for production.
        "regulatory_impact": _clamp(profile.data_sensitivity + (1 if profile.is_production else 0)),
        "asset_criticality": _clamp(profile.criticality),
        "blast_radius": BLAST_RADIUS.get(result.resource_type, 3),
        # A failing control is by definition not providing its protection.
        "control_effectiveness": 0,
        "age_days": max(0, int(age_days)),
    }


def score_result(*, profile: TargetProfile, result, rule_category: str, age_days: int = 0):
    """Return ``(inputs, Score)`` for one control result."""
    inputs = risk_inputs(profile=profile, result=result, rule_category=rule_category, age_days=age_days)
    return inputs, calculate(inputs)


def compliance_score(results: Iterable) -> Decimal:
    """Severity-weighted proportion of applicable controls that passed.

    Informational only. It never overrides a blocker: a deployment can score 96%
    and still be blocked, which is the correct outcome when the missing 4% is a
    publicly exposed database.
    """
    numerator = Decimal("0")
    denominator = Decimal("0")
    for result in results:
        if result.outcome in {Outcome.NOT_APPLICABLE, Outcome.ERROR}:
            continue
        weight = Decimal(max(1, int(result.severity)))
        denominator += weight
        if result.outcome == Outcome.PASS:
            numerator += weight
        elif result.outcome == Outcome.WARNING:
            numerator += weight * Decimal("0.5")
    if denominator == 0:
        return Decimal("100.00")
    return (Decimal("100") * numerator / denominator).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def deployment_risk(residuals: Sequence[Decimal]) -> Decimal:
    """Aggregate individual residual risks into one deployment risk.

    Takes the highest residual plus a tenth of the next four. Averaging would
    let a single critical failure disappear into a large, mostly-clean plan;
    summing would make any large deployment look catastrophic. This keeps the
    worst finding dominant while still reflecting accumulation.
    """
    if not residuals:
        return Decimal("0.00")
    ordered = sorted(residuals, reverse=True)
    total = ordered[0] + Decimal("0.10") * sum(ordered[1:5], Decimal("0"))
    return min(Decimal("100"), total).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class DecisionOutcome:
    decision: str
    reason_codes: list[str]
    compliance: Decimal
    risk: Decimal
    counts: dict
    blocking_fingerprints: list[str]


def decide(
    *, profile: TargetProfile, results: Sequence, thresholds, risk_total: Decimal, had_error: bool
) -> DecisionOutcome:
    """Turn results and an aggregate risk into the gate decision.

    Evaluated strictly in this order:

    1. evaluation error on a protected target -> ``error`` (fail closed);
    2. any unwaived blocking-rule failure -> ``blocked``;
    3. any unwaived critical failure on production or an exposed target -> ``blocked``;
    4. aggregate risk against the configured thresholds;
    5. outstanding manual review -> ``manual_review``.
    """
    counts: dict[str, int] = {}
    for result in results:
        counts[result.outcome] = counts.get(result.outcome, 0) + 1
    counts["waived"] = sum(1 for result in results if result.waived_by_id is not None)

    open_failures = [result for result in results if result.outcome == Outcome.FAIL and result.waived_by_id is None]
    blocking = [result for result in open_failures if result.blocking]
    critical = [result for result in open_failures if int(result.severity) >= 5]
    manual = [result for result in results if result.outcome == Outcome.MANUAL_REVIEW]

    reasons: list[str] = []
    decision = Decision.APPROVED

    if had_error:
        # Failing closed is the whole point of a gate. On a development target
        # an engine fault should not halt delivery, so it degrades to review.
        reasons.append("EVALUATION_ERROR")
        decision = Decision.ERROR if _is_protected(profile) else Decision.MANUAL_REVIEW
    elif blocking:
        reasons.append("MANDATORY_CONTROL_FAILED")
        decision = Decision.BLOCKED
    elif critical and thresholds.block_critical_on_production and _is_protected(profile):
        reasons.append("PRODUCTION_CRITICAL_FINDING")
        decision = Decision.BLOCKED
    elif risk_total >= Decimal(thresholds.block_at_risk):
        reasons.append("RISK_ABOVE_BLOCK_THRESHOLD")
        decision = Decision.BLOCKED
    elif risk_total >= Decimal(thresholds.manual_review_at_risk):
        reasons.append("RISK_REQUIRES_REVIEW")
        decision = Decision.MANUAL_REVIEW
    elif manual:
        reasons.append("MANUAL_CONTROL_OUTSTANDING")
        decision = Decision.MANUAL_REVIEW
    elif risk_total >= Decimal(thresholds.actions_at_risk) or open_failures:
        reasons.append("REMEDIATION_ACTIONS_REQUIRED")
        decision = Decision.APPROVED_WITH_ACTIONS
    else:
        reasons.append("ALL_MANDATORY_CONTROLS_PASSED")

    if counts.get("waived"):
        reasons.append("WAIVERS_APPLIED")

    return DecisionOutcome(
        decision=decision,
        reason_codes=reasons,
        compliance=compliance_score(results),
        risk=risk_total,
        counts=counts,
        blocking_fingerprints=sorted({result.fingerprint for result in (blocking or critical)}),
    )


def _is_protected(profile: TargetProfile) -> bool:
    return profile.is_production or profile.internet_exposed


def decision_hash(*, run, outcome: DecisionOutcome, thresholds) -> str:
    """Digest over everything that determined the decision.

    Deliberately includes the input, policy and engine identifiers: the same
    verdict reached from different inputs is not the same decision, and an
    auditor must be able to tell them apart.
    """
    return sha256_hex(
        canonical_json(
            {
                "evaluation_run_id": str(run.id),
                "input_hash": run.input_hash,
                "policy_hash": run.policy_hash,
                "engine_versions": run.engine_versions,
                "scoring_version": SCORING_VERSION,
                "risk_formula_version": FORMULA_VERSION,
                "threshold_profile": f"{thresholds.name}@{thresholds.profile_version}",
                "decision": outcome.decision,
                "compliance_score": str(outcome.compliance),
                "risk_score": str(outcome.risk),
                "reason_codes": outcome.reason_codes,
                "blocking_fingerprints": outcome.blocking_fingerprints,
            }
        )
    )
