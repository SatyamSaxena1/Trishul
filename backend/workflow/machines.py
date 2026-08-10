from .engine import MachineSpec, TransitionSpec


def _t(event, states, target):
    return TransitionSpec(event, frozenset(states), target)


EVALUATION = MachineSpec(
    name="deployment_evaluation",
    version=1,
    state_field="state",
    transitions=(
        _t("start", ["queued"], "normalizing"),
        _t("evaluate", ["normalizing"], "evaluating"),
        _t("decide", ["evaluating"], "deciding"),
        _t("complete", ["deciding"], "completed"),
        _t("fail", ["queued", "normalizing", "evaluating", "deciding"], "failed"),
        _t("retry", ["normalizing", "evaluating", "deciding"], "queued"),
        _t("cancel", ["queued", "normalizing", "evaluating", "deciding"], "cancelled"),
    ),
)

ENGAGEMENT = MachineSpec(
    name="engagement",
    version=1,
    state_field="status",
    transitions=(
        _t("activate", ["draft"], "active"),
        _t("close", ["active"], "closed"),
        _t("revoke", ["draft", "active"], "revoked"),
    ),
)

CONTROL = MachineSpec(
    name="organisation_control",
    version=1,
    state_field="status",
    transitions=(
        _t("submit_evidence", ["not_started", "evidence_submitted"], "evidence_submitted"),
        _t("start_review", ["evidence_submitted"], "under_review"),
        _t("raise_query", ["not_started", "evidence_submitted", "under_review"], "under_review"),
        _t("mark_compliant", ["not_started", "under_review", "evidence_submitted"], "compliant"),
        _t("mark_partial", ["not_started", "under_review", "evidence_submitted"], "partially_compliant"),
        _t("mark_noncompliant", ["not_started", "under_review", "evidence_submitted"], "noncompliant"),
        _t("mark_not_applicable", ["not_started", "under_review", "evidence_submitted"], "not_applicable"),
        _t("reopen", ["compliant", "partially_compliant", "noncompliant", "not_applicable"], "under_review"),
    ),
)
