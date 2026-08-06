"""OSCAL interchange.

NIST OSCAL is used as the *export and traceability* format, not as the
operational data model. Querying raw OSCAL JSON to make a deployment decision
would be slow and would put a document format on the critical path; instead the
relational schema stays authoritative and OSCAL is generated from it.

What this produces is an Assessment Results document: the run as the assessment
activity, each control result as an observation, each unwaived failure as a
finding, and the deployment decision as the overall risk statement. That is the
artifact an auditor or a GRC platform can ingest without knowing anything about
Trishul's internals.

Scope note: this is automated technical assessment evidence, not certification,
legal compliance, organisation-wide compliance, or a final auditor opinion.
"""

import re
import uuid

from .models import ControlMapping, ControlResult, DeploymentDecision, Outcome

OSCAL_VERSION = "1.1.2"

# OSCAL observation/finding vocabulary. "satisfied" and "not-satisfied" are the
# assessment-results states; Trishul's richer outcomes are carried alongside in
# a property so no fidelity is lost in translation.
_OSCAL_STATE = {
    Outcome.PASS: "satisfied",
    Outcome.FAIL: "not-satisfied",
    Outcome.WARNING: "not-satisfied",
    Outcome.MANUAL_REVIEW: "not-satisfied",
    Outcome.NOT_APPLICABLE: "not-applicable",
    Outcome.NOT_EVALUATED: "not-satisfied",
    Outcome.ERROR: "not-satisfied",
}


def _uuid(value) -> str:
    return str(value)


def _properties(pairs) -> list[dict]:
    return [{"name": name, "value": str(value)} for name, value in pairs if value not in (None, "")]


def _token(value: str) -> str:
    """Render framework identifiers as OSCAL's NCName-compatible token."""
    token = re.sub(r"[^A-Za-z0-9._-]", "-", value)
    return token if token[:1].isalpha() or token.startswith("_") else f"control-{token}"


def assessment_results(run) -> dict:
    """Render one completed ``EvaluationRun`` as OSCAL Assessment Results."""
    results = list(
        ControlResult.all_objects.filter(tenant=run.tenant, evaluation_run=run)
        .select_related("policy_rule", "policy_rule__unified_control", "gap", "risk")
        .order_by("resource_type", "resource_id", "id")
    )
    decision = DeploymentDecision.all_objects.filter(tenant=run.tenant, evaluation_run=run).first()
    mappings: dict[str, list[ControlMapping]] = {}
    for mapping in ControlMapping.all_objects.filter(
        tenant=run.tenant, policy_rule__policy_pack=run.policy_pack
    ).select_related("policy_rule"):
        mappings.setdefault(mapping.policy_rule.stable_key, []).append(mapping)
    reviewed_control_ids = sorted({_token(mapping.control_id) for values in mappings.values() for mapping in values})

    observations = []
    findings = []
    for result in results:
        rule_key = result.policy_rule.stable_key
        observation_uuid = _uuid(result.id)
        observations.append(
            {
                "uuid": observation_uuid,
                "title": f"{rule_key} — {result.resource_type} {result.resource_id}",
                "description": result.rationale,
                "methods": ["TEST"],
                "types": ["control-objective"],
                "subjects": [
                    {
                        "subject-uuid": observation_uuid,
                        "type": "component",
                        "title": result.resource_id,
                        "props": _properties(
                            [
                                ("resource-type", result.resource_type),
                                ("resource-path", result.resource_path),
                            ]
                        ),
                    }
                ],
                "props": _properties(
                    [
                        ("rule-id", rule_key),
                        ("rule-version", result.policy_rule.rule_version),
                        ("outcome", result.outcome),
                        ("state", _OSCAL_STATE.get(result.outcome, "not-satisfied")),
                        ("reason-code", result.reason_code),
                        ("severity", result.severity),
                        ("confidence", result.confidence),
                        ("fingerprint", result.fingerprint),
                        (
                            "unified-control-objective",
                            result.policy_rule.unified_control.code if result.policy_rule.unified_control else "",
                        ),
                        ("evidence-hash", run.result_manifest_hash),
                        ("evidence-reference", run.result_manifest_key),
                        ("gap-id", result.gap_id),
                        ("risk-id", result.risk_id),
                        (
                            "remediation-id",
                            result.gap.remediations.values_list("id", flat=True).first() if result.gap_id else "",
                        ),
                        ("waiver-id", result.waived_by_id),
                        ("waived", "true" if result.waived_by_id else "false"),
                        ("residual-risk", result.residual_risk),
                    ]
                ),
                "collected": run.started_at.isoformat() if run.started_at else run.created_at.isoformat(),
            }
        )
        if result.outcome == Outcome.FAIL and result.waived_by_id is None:
            for mapping in mappings.get(rule_key, ()):
                findings.append(
                    {
                        "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{result.id}:{mapping.control_id}")),
                        "title": f"{mapping.framework} {mapping.control_id}: {result.policy_rule.title}",
                        "description": result.rationale,
                        "target": {
                            "type": "objective-id",
                            "target-id": _token(mapping.control_id),
                            "status": {"state": "not-satisfied"},
                            "props": _properties(
                                [
                                    ("framework", mapping.framework),
                                    ("framework-version", mapping.framework_version),
                                    ("control-id", mapping.control_id),
                                    # Traceability, not a certification claim.
                                    ("mapping-basis", "control-traceability"),
                                ]
                            ),
                        },
                        "props": _properties([("remediation-guidance", result.policy_rule.remediation_guidance)]),
                        "related-observations": [{"observation-uuid": observation_uuid}],
                    }
                )

    return {
        "assessment-results": {
            "uuid": _uuid(run.id),
            "metadata": {
                "title": f"Deployment assurance results — {run.target.name}",
                "last-modified": (run.completed_at or run.created_at).isoformat(),
                "version": str(run.version),
                "oscal-version": OSCAL_VERSION,
                "props": _properties(
                    [
                        ("input-hash", run.input_hash),
                        ("tenant-id", run.tenant_id),
                        ("application-id", run.target.application_id),
                        ("deployment-target-id", run.target_id),
                        ("evaluation-run-id", run.id),
                        ("policy-hash", run.policy_hash),
                        ("policy-pack", f"{run.policy_pack.key}@{run.policy_pack.pack_version}"),
                        ("engine-version", (run.engine_versions or {}).get("engine", "")),
                        ("target-environment", run.target.environment),
                        ("provider", run.target.provider),
                    ]
                ),
            },
            "import-ap": {"href": f"#{run.policy_pack.content_hash}"},
            "results": [
                {
                    "uuid": _uuid(run.correlation_id),
                    "title": "Deterministic deployment control evaluation",
                    "description": (
                        "Automated evaluation of a normalized deployment snapshot against a "
                        "signed, content-addressed policy pack."
                    ),
                    "start": (run.started_at or run.created_at).isoformat(),
                    "end": (run.completed_at or run.created_at).isoformat(),
                    "reviewed-controls": {
                        "description": "Framework controls traced to the evaluated deployment rules.",
                        "control-selections": [
                            {"include-controls": [{"control-id": control_id} for control_id in reviewed_control_ids]}
                            if reviewed_control_ids
                            else {"include-all": {}}
                        ],
                    },
                    "observations": observations,
                    "findings": findings,
                    "risks": _risks(decision),
                }
            ],
        }
    }


def _risks(decision) -> list[dict]:
    if decision is None:
        return []
    return [
        {
            "uuid": _uuid(decision.id),
            "title": f"Deployment decision: {decision.decision}",
            "description": (
                f"Aggregate deployment risk {decision.risk_score}; "
                f"weighted control compliance {decision.compliance_score}%."
            ),
            "statement": ", ".join(decision.reason_codes),
            "status": "open" if not decision.permits_deployment else "closed",
            "props": _properties(
                [
                    ("decision", decision.decision),
                    ("decision-hash", decision.decision_hash),
                    ("risk-score", decision.risk_score),
                    ("compliance-score", decision.compliance_score),
                    (
                        "threshold-profile",
                        f"{decision.threshold_profile.name}@{decision.threshold_profile.profile_version}",
                    ),
                ]
            ),
        }
    ]
