"""End-to-end evaluation: snapshot in, decision and evidence out."""

import uuid
from decimal import Decimal

import pytest
from django.utils import timezone

from core.models import AuditEvent, AuditorVerdict, ComplianceGap, Remediation, Risk, Task
from core.tenancy import tenant_context
from deployment_assurance import decisions, evaluation
from deployment_assurance.limits import UnsafeArtifact
from deployment_assurance.models import (
    ControlResult,
    Decision,
    DeploymentDecision,
    Environment,
    EvaluationRun,
    EvidenceArtifact,
    ExceptionWaiver,
    Outcome,
    PolicyRule,
)
from deployment_assurance.resources import sha256_hex

from .conftest import terraform_plan

pytestmark = pytest.mark.django_db

OPEN_SSH = (
    "aws_security_group.bastion",
    "aws_security_group",
    {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
)
ENCRYPTED_BUCKET = (
    "aws_s3_bucket.audit",
    "aws_s3_bucket",
    {"bucket": "audit", "server_side_encryption_configuration": [{"rule": {}}], "block_public_access": True},
)
CLEAN_BUCKET = ENCRYPTED_BUCKET
RESTRICTED_SSH = (
    "aws_security_group.bastion",
    "aws_security_group",
    {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}]},
)


def test_open_admin_port_blocks_deployment(target, submit, run_evaluation):
    snapshot = submit(target, terraform_plan(OPEN_SSH))
    run, decision = run_evaluation(snapshot)

    assert run.state == EvaluationRun.State.COMPLETED
    assert decision.decision == Decision.BLOCKED
    assert "MANDATORY_CONTROL_FAILED" in decision.reason_codes
    assert not decision.permits_deployment

    with tenant_context(target.tenant_id):
        failure = ControlResult.objects.get(evaluation_run=run, outcome=Outcome.FAIL, reason_code="PUBLIC_ADMIN_PORT")
    assert failure.blocking is True
    assert failure.severity == 5


def test_clean_plan_is_approved(make_target, submit, run_evaluation):
    target = make_target(
        name="payments-dev",
        slug="payments-dev",
        external_id="dev-stack",
        environment=Environment.DEVELOPMENT,
        internet_exposed=False,
        criticality=2,
        data_sensitivity=2,
    )
    _, decision = run_evaluation(submit(target, terraform_plan(CLEAN_BUCKET)))
    assert decision.decision == Decision.APPROVED
    assert decision.reason_codes == ["ALL_MANDATORY_CONTROLS_PASSED"]
    assert decision.compliance_score == Decimal("100.00")


def test_rejected_artifact_error_does_not_echo_content(target, submit, policy_profile, monkeypatch):
    snapshot = submit(target, terraform_plan(CLEAN_BUCKET))
    with tenant_context(target.tenant_id):
        run = EvaluationRun.objects.create(
            tenant=target.tenant,
            snapshot=snapshot,
            target=target,
            policy_pack=policy_profile.policy_pack,
            policy_profile=policy_profile,
            requested_by_type="user",
            requested_by_id="test",
        )

    def reject(**_kwargs):
        raise UnsafeArtifact("raw-secret-value")

    monkeypatch.setattr(evaluation, "normalize_deployment", reject)
    with pytest.raises(evaluation.EvaluationError, match="artifact_rejected:UnsafeArtifact") as caught:
        evaluation.evaluate_snapshot(run)
    assert "raw-secret-value" not in str(caught.value)


def test_evaluation_records_hashed_evidence_for_every_stage(target, submit, run_evaluation, object_store):
    run, decision = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    with tenant_context(target.tenant_id):
        roles = set(EvidenceArtifact.objects.filter(target=target).values_list("role", flat=True))
        artifacts = list(EvidenceArtifact.objects.filter(evaluation_run=run))
    assert roles == {
        EvidenceArtifact.Role.SOURCE_ARTIFACT,
        EvidenceArtifact.Role.NORMALIZED_SNAPSHOT,
        EvidenceArtifact.Role.RESULT_MANIFEST,
        EvidenceArtifact.Role.DECISION_ENVELOPE,
    }
    # Every recorded digest must match the bytes actually stored.
    for artifact in artifacts:
        assert sha256_hex(object_store[artifact.object_key]) == artifact.sha256
        assert artifact.envelope["content"]["sha256"] == artifact.sha256
    assert decision.decision_hash


def test_evaluation_is_deterministic(target, submit, run_evaluation):
    """The same artifact, pack and engine must produce the same result content."""
    payload = terraform_plan(OPEN_SSH, CLEAN_BUCKET)
    first_run, first_decision = run_evaluation(submit(target, payload))
    second_run, second_decision = run_evaluation(submit(target, payload))

    assert first_run.input_hash == second_run.input_hash
    assert first_run.policy_hash == second_run.policy_hash
    # The run-independent result content must be byte-identical.
    assert first_run.summary["results_hash"] == second_run.summary["results_hash"]
    assert first_decision.decision == second_decision.decision
    assert first_decision.risk_score == second_decision.risk_score
    assert first_decision.decision_hash != second_decision.decision_hash, (
        "the envelope is bound to the run id, so two runs are distinguishable"
    )

    with tenant_context(target.tenant_id):

        def signature(run):
            return sorted(ControlResult.objects.filter(evaluation_run=run).values_list("fingerprint", "outcome"))

        assert signature(first_run) == signature(second_run)


def test_failure_creates_a_traceable_risk_register_entry(target, submit, run_evaluation):
    run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    with tenant_context(target.tenant_id):
        result = ControlResult.objects.get(evaluation_run=run, reason_code="PUBLIC_ADMIN_PORT")
        risk = Risk.objects.get(pk=result.risk_id)
        link = risk.links.get()
        score = risk.scores.get()
    assert risk.application_id == target.application_id
    assert link.source_type == "core.compliancegap"
    assert str(link.source_id) == str(result.gap_id)
    # The retained inputs are what make the score reproducible and explainable.
    assert score.inputs["control_effectiveness"] == 0
    assert score.inputs["asset_criticality"] == target.criticality


def test_repeated_failure_reuses_one_gap_risk_and_task(target, submit, run_evaluation):
    first_run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    second_run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    with tenant_context(target.tenant_id):
        first = ControlResult.objects.get(evaluation_run=first_run, reason_code="PUBLIC_ADMIN_PORT")
        second = ControlResult.objects.get(evaluation_run=second_run, reason_code="PUBLIC_ADMIN_PORT")
        assert first.gap_id == second.gap_id
        assert first.risk_id == second.risk_id
        assert ComplianceGap.objects.filter(pk=first.gap_id).count() == 1
        assert Remediation.objects.filter(gap_id=first.gap_id).count() == 1
        assert Task.objects.filter(gap_id=first.gap_id, task_type="deployment_remediation").count() == 1


def test_corrected_evaluation_closes_the_active_chain(target, submit, run_evaluation):
    failed_run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    run_evaluation(submit(target, terraform_plan(RESTRICTED_SSH)))
    with tenant_context(target.tenant_id):
        failed = ControlResult.objects.get(evaluation_run=failed_run, reason_code="PUBLIC_ADMIN_PORT")
        gap = ComplianceGap.objects.get(pk=failed.gap_id)
        risk = Risk.objects.get(pk=failed.risk_id)
        remediation = Remediation.objects.get(gap=gap)
        task = Task.objects.get(gap=gap, task_type="deployment_remediation")
    assert gap.status == "closed"
    assert gap.closed_at is not None
    assert risk.state == "mitigated"
    assert remediation.status == "completed"
    assert task.status == Task.Status.COMPLETED


def test_corrected_evidence_never_changes_a_locked_control(target, submit, run_evaluation, django_user_model):
    failed_run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    with tenant_context(target.tenant_id):
        failed = ControlResult.objects.get(evaluation_run=failed_run, reason_code="PUBLIC_ADMIN_PORT")
        reviewer = django_user_model.objects.create(username="locking-auditor")
        verdict = AuditorVerdict.objects.create(
            tenant=target.tenant,
            engagement_id=uuid.uuid4(),
            organisation_control=failed.gap.organisation_control,
            decision=AuditorVerdict.Decision.NONCOMPLIANT,
            rationale="Final audit verdict.",
            evidence_result_id=failed.id,
            finalized_by=reviewer,
        )
    run_evaluation(submit(target, terraform_plan(RESTRICTED_SSH)))
    with tenant_context(target.tenant_id):
        failed.gap.refresh_from_db()
        notification = Task.objects.get(task_type="auditor_change_review", source_id=verdict.id)
    assert failed.gap.status == "open"
    assert notification.owner_id == reviewer.id


def test_approved_waiver_suppresses_the_blocker(target, submit, run_evaluation, django_user_model):
    """A scoped, approved, unexpired waiver clears the block it names."""
    blocked_run, blocked_decision = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    assert blocked_decision.decision == Decision.BLOCKED

    with tenant_context(target.tenant_id):
        result = ControlResult.objects.get(evaluation_run=blocked_run, reason_code="PUBLIC_ADMIN_PORT")
        rule = PolicyRule.objects.get(pk=result.policy_rule_id)
        requester = django_user_model.objects.create(username="requester")
        approver = django_user_model.objects.create(username="approver")
        ExceptionWaiver.objects.create(
            tenant=target.tenant,
            target=target,
            policy_rule=rule,
            rule_version=rule.rule_version,
            resource_fingerprint=result.fingerprint,
            reason="Vendor support path pending private connectivity.",
            status=ExceptionWaiver.Status.APPROVED,
            expires_at=timezone.now() + timezone.timedelta(days=7),
            requested_by=requester,
            approved_by=approver,
        )

    _, decision = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    assert decision.decision != Decision.BLOCKED
    assert "WAIVERS_APPLIED" in decision.reason_codes


def test_expired_waiver_does_not_suppress_the_blocker(target, submit, run_evaluation, django_user_model):
    blocked_run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    with tenant_context(target.tenant_id):
        result = ControlResult.objects.get(evaluation_run=blocked_run, reason_code="PUBLIC_ADMIN_PORT")
        rule = PolicyRule.objects.get(pk=result.policy_rule_id)
        requester = django_user_model.objects.create(username="requester")
        approver = django_user_model.objects.create(username="approver")
        ExceptionWaiver.objects.create(
            tenant=target.tenant,
            target=target,
            policy_rule=rule,
            rule_version=rule.rule_version,
            resource_fingerprint=result.fingerprint,
            reason="Lapsed exception.",
            status=ExceptionWaiver.Status.APPROVED,
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
            requested_by=requester,
            approved_by=approver,
        )
    _, decision = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    assert decision.decision == Decision.BLOCKED


def test_waiver_bound_to_an_older_rule_version_does_not_apply(target, submit, run_evaluation, django_user_model):
    """A waiver approved against different rule logic must not carry forward."""
    blocked_run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    with tenant_context(target.tenant_id):
        result = ControlResult.objects.get(evaluation_run=blocked_run, reason_code="PUBLIC_ADMIN_PORT")
        rule = PolicyRule.objects.get(pk=result.policy_rule_id)
        requester = django_user_model.objects.create(username="requester")
        approver = django_user_model.objects.create(username="approver")
        ExceptionWaiver.objects.create(
            tenant=target.tenant,
            target=target,
            policy_rule=rule,
            rule_version="0.9.0",
            resource_fingerprint=result.fingerprint,
            reason="Approved against superseded rule logic.",
            status=ExceptionWaiver.Status.APPROVED,
            expires_at=timezone.now() + timezone.timedelta(days=7),
            requested_by=requester,
            approved_by=approver,
        )
    _, decision = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    assert decision.decision == Decision.BLOCKED


def test_rejected_artifact_fails_the_run_without_a_decision(target, submit, run_evaluation):
    from deployment_assurance.evaluation import EvaluationError

    snapshot = submit(target, b'{"not": "a plan"}')
    with pytest.raises(EvaluationError):
        run_evaluation(snapshot)
    with tenant_context(target.tenant_id):
        assert not DeploymentDecision.objects.filter(target=target).exists()


def test_decision_supersedes_the_previous_one(target, submit, run_evaluation):
    _, first = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    _, second = run_evaluation(submit(target, terraform_plan(CLEAN_BUCKET)))
    first.refresh_from_db()
    assert first.superseded_by_id == second.id
    assert second.superseded_by_id is None


def test_decision_is_written_to_the_audit_ledger(target, submit, run_evaluation):
    run, decision = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    event = AuditEvent.all_objects.filter(tenant=target.tenant, action="deployment.decision.recorded").latest(
        "occurred_at"
    )
    assert event.details["decision"] == decision.decision
    assert event.details["decision_hash"] == decision.decision_hash
    assert event.details["evaluation_run_id"] == str(run.id)


def test_unmapped_resource_types_are_reported_not_passed(target, submit, run_evaluation, object_store):
    """A resource no rule understands must be visible in the manifest."""
    payload = terraform_plan(
        ("aws_instance.web", "aws_instance", {"ami": "ami-1", "metadata_options": [{"http_tokens": "required"}]})
    )
    run, _ = run_evaluation(submit(target, payload))
    import json

    manifest = json.loads(object_store[run.result_manifest_key])
    assert "unevaluated_resource_types" in manifest
    assert manifest["input_hash"] == run.input_hash


# --- Scoring units --------------------------------------------------------


def test_compliance_score_excludes_not_applicable():
    class Stub:
        def __init__(self, outcome, severity):
            self.outcome, self.severity = outcome, severity

    results = [Stub(Outcome.PASS, 3), Stub(Outcome.NOT_APPLICABLE, 5), Stub(Outcome.FAIL, 3)]
    assert decisions.compliance_score(results) == Decimal("50.00")


def test_compliance_score_of_an_empty_applicable_set_is_full():
    assert decisions.compliance_score([]) == Decimal("100.00")


def test_deployment_risk_keeps_the_worst_finding_dominant():
    """Accumulation is reflected, but never dilutes a single critical failure."""
    assert decisions.deployment_risk([]) == Decimal("0.00")
    assert decisions.deployment_risk([Decimal("80")]) == Decimal("80.00")
    # Nine low-risk findings must not outweigh one severe one.
    assert decisions.deployment_risk([Decimal("80"), *[Decimal("10")] * 9]) == Decimal("84.00")
    assert decisions.deployment_risk([Decimal("100"), Decimal("100")]) == Decimal("100.00")
