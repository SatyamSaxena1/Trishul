"""API contract: authorization, tenant isolation, concurrency and the gate flow."""

import json
import os
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from jsonschema import Draft7Validator
from rest_framework.test import APIClient

from core.models import Application, Membership, Organization, ServiceAccount, Tenant, Workspace
from core.tenancy import tenant_context
from deployment_assurance import permissions as perms
from deployment_assurance.models import (
    Decision,
    DeploymentSnapshot,
    DeploymentTarget,
    Environment,
    EvaluationRun,
    ExceptionWaiver,
    Provider,
    SourceType,
)

from .conftest import terraform_plan

pytestmark = pytest.mark.django_db

BASE = "/api/v1/assurance"
OPEN_SSH = (
    "aws_security_group.bastion",
    "aws_security_group",
    {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
)

CI_SCOPES = [
    perms.TARGET_READ,
    perms.SNAPSHOT_SUBMIT,
    perms.SNAPSHOT_READ,
    perms.EVALUATION_CREATE,
    perms.EVALUATION_READ,
    perms.DECISION_READ,
]


def issue(tenant, scopes, *, name="ci", application_ids=()):
    _, token = ServiceAccount.issue(
        tenant=tenant,
        name=name,
        scopes=list(scopes),
        application_ids=list(application_ids),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return token


def auth(token):
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def upload(client, token, target, payload=None, source_type=SourceType.TERRAFORM_PLAN):
    return client.post(
        f"{BASE}/deployment-snapshots/",
        {
            "target": str(target.id),
            "source_type": source_type,
            "artifact": SimpleUploadedFile("plan.json", payload or terraform_plan(OPEN_SSH), "application/json"),
            "source_reference": "example/infra@6f8a0c1",
        },
        format="multipart",
        **auth(token),
    )


# --- Gate flow ------------------------------------------------------------


def test_submit_evaluate_and_read_decision(target, object_store, run_evaluation):
    client = APIClient()
    token = issue(target.tenant, CI_SCOPES)

    response = upload(client, token, target)
    assert response.status_code == 201, response.data
    snapshot_id = response.json()["id"]
    assert response.json()["ingestion_state"] == DeploymentSnapshot.IngestionState.READY
    # The hash is computed server-side from the received bytes.
    assert response.json()["artifact_sha256"] == __import__("hashlib").sha256(terraform_plan(OPEN_SSH)).hexdigest()

    response = client.post(
        f"{BASE}/deployment-snapshots/{snapshot_id}/evaluations/",
        {"trigger": EvaluationRun.Trigger.PULL_REQUEST, "context": {"pull_request_number": 417}},
        format="json",
        **auth(token),
    )
    assert response.status_code == 202
    run_id = response.json()["evaluation_run_id"]

    # Before the worker runs, the decision endpoint reports pending, not absent.
    pending = client.get(f"{BASE}/evaluation-runs/{run_id}/decision/", **auth(token))
    assert pending.status_code == 409
    assert pending.json()["code"] == "DECISION_PENDING"

    with tenant_context(target.tenant_id):
        from deployment_assurance.evaluation import evaluate_snapshot

        evaluate_snapshot(
            EvaluationRun.objects.select_related(
                "tenant", "target", "target__application", "snapshot", "policy_pack", "policy_profile"
            ).get(pk=run_id)
        )

    decision = client.get(f"{BASE}/evaluation-runs/{run_id}/decision/", **auth(token))
    assert decision.status_code == 200
    assert decision.json()["decision"] == Decision.BLOCKED
    assert decision.json()["integrity_verified"] is True

    results = client.get(f"{BASE}/evaluation-runs/{run_id}/results/?outcome=fail", **auth(token))
    assert results.status_code == 200
    assert any(item["reason_code"] == "PUBLIC_ADMIN_PORT" for item in results.json()["results"])

    oscal = client.get(f"{BASE}/evaluation-runs/{run_id}/oscal-results/", **auth(token))
    assert oscal.status_code == 200
    export = oscal.json()
    document = export["assessment-results"]
    assert document["metadata"]["oscal-version"]
    assert document["results"][0]["findings"], "an unwaived failure must appear as an OSCAL finding"
    if schema_path := os.environ.get("OSCAL_SCHEMA_PATH"):
        with open(schema_path, encoding="utf-8") as handle:
            schema = json.load(handle)
        # NIST uses the ECMA-262 Unicode property syntax, unsupported by
        # Python's stdlib regex engine. This is its Python-equivalent token
        # expression; every other official schema constraint stays untouched.
        schema["definitions"]["TokenDatatype"]["pattern"] = r"^(?:[^\W\d]|_)(?:[^\W\d]|\d|[.\-_])*$"
        Draft7Validator.check_schema(schema)
        Draft7Validator(schema).validate(export)


def test_idempotency_key_replays_the_original_run(target, object_store):
    client = APIClient()
    token = issue(target.tenant, CI_SCOPES)
    snapshot_id = upload(client, token, target).json()["id"]
    headers = {**auth(token), "HTTP_IDEMPOTENCY_KEY": "pr-417-attempt-1"}

    first = client.post(f"{BASE}/deployment-snapshots/{snapshot_id}/evaluations/", {}, format="json", **headers)
    second = client.post(f"{BASE}/deployment-snapshots/{snapshot_id}/evaluations/", {}, format="json", **headers)
    assert first.status_code == second.status_code == 202
    assert first.json()["evaluation_run_id"] == second.json()["evaluation_run_id"]
    with tenant_context(target.tenant_id):
        assert EvaluationRun.objects.count() == 1


def test_evaluation_can_be_cancelled_with_version_and_idempotency(target, object_store):
    client = APIClient()
    token = issue(target.tenant, CI_SCOPES)
    snapshot_id = upload(client, token, target).json()["id"]
    run_id = client.post(
        f"{BASE}/deployment-snapshots/{snapshot_id}/evaluations/", {}, format="json", **auth(token)
    ).json()["evaluation_run_id"]
    url = f"{BASE}/evaluation-runs/{run_id}/transition/"

    available = client.get(f"{BASE}/evaluation-runs/{run_id}/available-transitions/", **auth(token))
    assert available.json()["events"] == ["cancel"]
    assert client.post(url, {"event": "cancel"}, format="json", **auth(token)).status_code == 428
    headers = {**auth(token), "HTTP_IF_MATCH": str(available.json()["version"]), "HTTP_IDEMPOTENCY_KEY": "cancel-1"}
    cancelled = client.post(url, {"event": "cancel", "reason": "Superseded build."}, format="json", **headers)
    replay = client.post(url, {"event": "cancel", "reason": "Superseded build."}, format="json", **headers)
    assert cancelled.status_code == replay.status_code == 200
    assert cancelled.json()["state"] == replay.json()["state"] == EvaluationRun.State.CANCELLED


def test_unsupported_source_type_is_rejected(target, object_store):
    client = APIClient()
    token = issue(target.tenant, CI_SCOPES)
    response = client.post(
        f"{BASE}/deployment-snapshots/",
        {
            "target": str(target.id),
            "source_type": "not_a_source_type",
            "artifact": SimpleUploadedFile("x.json", b"{}", "application/json"),
        },
        format="multipart",
        **auth(token),
    )
    assert response.status_code == 400


# --- Authorization --------------------------------------------------------


def test_missing_scope_is_denied(target, object_store):
    client = APIClient()
    token = issue(target.tenant, [perms.TARGET_READ], name="read-only")
    assert upload(client, token, target).status_code == 403


def test_service_account_cannot_approve_a_waiver(target, object_store, django_user_model):
    """Human-only permissions are refused even if the token carries the scope."""
    client = APIClient()
    token = issue(target.tenant, [*CI_SCOPES, perms.EXCEPTION_APPROVE], name="over-scoped")
    with tenant_context(target.tenant_id):
        from deployment_assurance.models import PolicyRule

        rule = PolicyRule.objects.filter(stable_key="DA-NET-001").get()
        requester = django_user_model.objects.create(username="requester")
        waiver = ExceptionWaiver.objects.create(
            tenant=target.tenant,
            target=target,
            policy_rule=rule,
            rule_version=rule.rule_version,
            resource_fingerprint="f" * 64,
            reason="Temporary.",
            expires_at=timezone.now() + timedelta(days=1),
            requested_by=requester,
        )
    response = client.post(
        f"{BASE}/exception-waivers/{waiver.id}/approve/",
        {"decision": "approved", "reason": "ok"},
        format="json",
        **auth(token),
    )
    assert response.status_code == 403
    waiver.refresh_from_db()
    assert waiver.status == ExceptionWaiver.Status.REQUESTED


def test_requester_cannot_approve_their_own_waiver(target, object_store, django_user_model):
    with tenant_context(target.tenant_id):
        from deployment_assurance.models import PolicyRule

        rule = PolicyRule.objects.filter(stable_key="DA-NET-001").get()
        user = django_user_model.objects.create(username="self-approver")
        Membership.all_objects.create(tenant=target.tenant, user=user, role=Membership.Role.CISO)
        waiver = ExceptionWaiver.objects.create(
            tenant=target.tenant,
            target=target,
            policy_rule=rule,
            rule_version=rule.rule_version,
            resource_fingerprint="f" * 64,
            reason="Temporary.",
            expires_at=timezone.now() + timedelta(days=1),
            requested_by=user,
        )
    client = APIClient()
    client.force_authenticate(user=user)
    response = client.post(
        f"{BASE}/exception-waivers/{waiver.id}/approve/",
        {"decision": "approved", "reason": "looks fine to me"},
        format="json",
    )
    assert response.status_code == 400
    waiver.refresh_from_db()
    assert waiver.status == ExceptionWaiver.Status.REQUESTED


def test_independent_approver_can_approve(target, object_store, django_user_model):
    with tenant_context(target.tenant_id):
        from deployment_assurance.models import PolicyRule

        rule = PolicyRule.objects.filter(stable_key="DA-NET-001").get()
        requester = django_user_model.objects.create(username="requester")
        approver = django_user_model.objects.create(username="ciso")
        Membership.all_objects.create(tenant=target.tenant, user=approver, role=Membership.Role.CISO)
        waiver = ExceptionWaiver.objects.create(
            tenant=target.tenant,
            target=target,
            policy_rule=rule,
            rule_version=rule.rule_version,
            resource_fingerprint="f" * 64,
            reason="Compensating controls in place.",
            expires_at=timezone.now() + timedelta(days=1),
            requested_by=requester,
        )
    client = APIClient()
    client.force_authenticate(user=approver)
    response = client.post(
        f"{BASE}/exception-waivers/{waiver.id}/approve/",
        {"decision": "approved", "reason": "Source allowlist and session recording verified."},
        format="json",
    )
    assert response.status_code == 200
    waiver.refresh_from_db()
    assert waiver.status == ExceptionWaiver.Status.APPROVED
    assert waiver.approved_by_id == approver.id


def test_application_scope_restricts_target_creation(tenant, application, policy_profile, object_store):
    with tenant_context(tenant.id):
        other_workspace = application.workspace
        other = Application.objects.create(tenant=tenant, workspace=other_workspace, name="unrelated")
    token = issue(
        tenant,
        [perms.TARGET_READ, perms.TARGET_WRITE],
        name="scoped",
        application_ids=[str(application.id)],
    )
    client = APIClient()
    response = client.post(
        f"{BASE}/deployment-targets/",
        {
            "application": str(other.id),
            "name": "forbidden",
            "slug": "forbidden",
            "provider": Provider.AWS,
            "target_type": DeploymentTarget.TargetType.CLUSTER,
            "environment": Environment.PRODUCTION,
            "external_id": "forbidden-stack",
        },
        format="json",
        **auth(token),
    )
    assert response.status_code == 403
    with tenant_context(tenant.id):
        assert not DeploymentTarget.objects.filter(slug="forbidden").exists()


# --- Tenant isolation -----------------------------------------------------


def test_targets_are_not_visible_across_tenants(target, object_store):
    other = Tenant.objects.create(slug="other", name="Other")
    token = issue(other, [perms.TARGET_READ], name="other-ci")
    client = APIClient()
    response = client.get(f"{BASE}/deployment-targets/", **auth(token))
    assert response.status_code == 200
    assert response.json()["results"] == []


def test_cross_tenant_target_detail_is_not_reachable(target, object_store):
    other = Tenant.objects.create(slug="other", name="Other")
    token = issue(other, [perms.TARGET_READ], name="other-ci")
    client = APIClient()
    assert client.get(f"{BASE}/deployment-targets/{target.id}/", **auth(token)).status_code == 404


def test_cannot_submit_a_snapshot_against_another_tenants_target(target, object_store):
    """The foreign target must not even be resolvable as a serializer choice."""
    other = Tenant.objects.create(slug="other", name="Other")
    with tenant_context(other.id):
        organization = Organization.objects.create(tenant=other, name="Other Org")
        workspace = Workspace.objects.create(tenant=other, organization=organization, name="W")
        Application.objects.create(tenant=other, workspace=workspace, name="A")
    token = issue(other, CI_SCOPES, name="other-ci")
    client = APIClient()
    response = upload(client, token, target)
    assert response.status_code == 400
    assert "target" in response.json()["errors"]


def test_cross_tenant_evaluation_run_is_not_readable(target, submit, run_evaluation, object_store):
    run, _ = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    other = Tenant.objects.create(slug="other", name="Other")
    token = issue(other, [perms.EVALUATION_READ, perms.DECISION_READ], name="other-ci")
    client = APIClient()
    assert client.get(f"{BASE}/evaluation-runs/{run.id}/", **auth(token)).status_code == 404
    assert client.get(f"{BASE}/evaluation-runs/{run.id}/decision/", **auth(token)).status_code == 404


# --- Concurrency and immutability ----------------------------------------


def test_target_update_requires_if_match(target, object_store):
    token = issue(target.tenant, [perms.TARGET_READ, perms.TARGET_WRITE], name="editor")
    client = APIClient()
    url = f"{BASE}/deployment-targets/{target.id}/"
    assert client.patch(url, {"region": "ap-south-1"}, format="json", **auth(token)).status_code == 428
    stale = client.patch(url, {"region": "ap-south-1"}, format="json", HTTP_IF_MATCH="99", **auth(token))
    assert stale.status_code == 412
    ok = client.patch(url, {"region": "ap-south-1"}, format="json", HTTP_IF_MATCH=str(target.version), **auth(token))
    assert ok.status_code == 200


def test_targets_cannot_be_deleted_while_evidence_exists(target, object_store):
    token = issue(target.tenant, [perms.TARGET_READ, perms.TARGET_WRITE], name="editor")
    client = APIClient()
    response = client.delete(
        f"{BASE}/deployment-targets/{target.id}/", HTTP_IF_MATCH=str(target.version), **auth(token)
    )
    assert response.status_code == 405


def test_decisions_and_results_are_read_only_over_http(target, submit, run_evaluation, object_store):
    run, decision = run_evaluation(submit(target, terraform_plan(OPEN_SSH)))
    token = issue(target.tenant, [perms.DECISION_READ, perms.EVALUATION_READ], name="reader")
    client = APIClient()
    assert client.delete(f"{BASE}/deployment-decisions/{decision.id}/", **auth(token)).status_code == 405
    assert client.post(f"{BASE}/deployment-decisions/", {}, format="json", **auth(token)).status_code == 405


def test_oscal_export_refuses_an_incomplete_run(target, object_store):
    client = APIClient()
    token = issue(target.tenant, CI_SCOPES)
    snapshot_id = upload(client, token, target).json()["id"]
    run_id = client.post(
        f"{BASE}/deployment-snapshots/{snapshot_id}/evaluations/", {}, format="json", **auth(token)
    ).json()["evaluation_run_id"]
    response = client.get(f"{BASE}/evaluation-runs/{run_id}/oscal-results/", **auth(token))
    assert response.status_code == 400


def test_problem_json_shape_is_preserved(target, object_store):
    token = issue(target.tenant, [perms.TARGET_READ], name="read-only")
    client = APIClient()
    body = upload(client, token, target).json()
    assert body["type"].startswith("urn:trishul:error:")
    assert body["status"] == 403
