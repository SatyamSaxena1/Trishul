"""Shared fixtures for Deployment Assurance tests.

Object storage is replaced with an in-memory dictionary. Evidence *content*
still flows through the real hashing and envelope code — only the S3 round trip
is substituted — so the determinism and integrity assertions stay meaningful.
"""

import json

import pytest
from django.utils import timezone

from core import runner
from core.models import Application, Organization, Tenant, Workspace
from core.tenancy import tenant_context
from deployment_assurance import evaluation, evidence
from deployment_assurance.models import (
    DecisionThresholdProfile,
    DeploymentSnapshot,
    DeploymentTarget,
    Environment,
    EvaluationRun,
    PolicyProfile,
    Provider,
    SourceType,
)
from deployment_assurance.policy.registry import sync_pack


@pytest.fixture
def object_store(monkeypatch):
    """In-memory stand-in for the S3-compatible object store."""
    store: dict[str, bytes] = {}

    def fake_store_bytes(key, payload, *, content_type):
        store[key] = payload

    def fake_download(key, filename):
        with open(filename, "wb") as handle:
            handle.write(store[key])

    monkeypatch.setattr(evidence, "store_bytes", fake_store_bytes)
    monkeypatch.setattr(runner, "download_file", fake_download)
    return store


@pytest.fixture
def tenant(db):
    return Tenant.objects.create(slug="acme", name="Acme")


@pytest.fixture
def application(tenant):
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name="Acme Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name="Platform")
        return Application.objects.create(
            tenant=tenant,
            workspace=workspace,
            name="payments",
            criticality=5,
            data_sensitivity=5,
            internet_exposed=True,
        )


@pytest.fixture
def policy_profile(tenant):
    with tenant_context(tenant.id):
        pack = sync_pack(tenant)
        thresholds = DecisionThresholdProfile.objects.create(
            tenant=tenant, name="production-default", profile_version="1.0.0", is_default=True
        )
        return PolicyProfile.objects.create(
            tenant=tenant,
            policy_pack=pack,
            threshold_profile=thresholds,
            name="baseline-default",
            is_default=True,
        )


@pytest.fixture
def make_target(tenant, application, policy_profile):
    def factory(**overrides):
        defaults = {
            "tenant": tenant,
            "application": application,
            "policy_profile": policy_profile,
            "name": "payments-production",
            "slug": "payments-production",
            "provider": Provider.AWS,
            "target_type": DeploymentTarget.TargetType.APPLICATION_STACK,
            "environment": Environment.PRODUCTION,
            "external_id": "arn:aws:cloudformation:ap-south-1:123456789012:stack/payments",
            "criticality": 5,
            "data_sensitivity": 5,
            "internet_exposed": True,
        }
        defaults.update(overrides)
        with tenant_context(tenant.id):
            return DeploymentTarget.objects.create(**defaults)

    return factory


@pytest.fixture
def target(make_target):
    return make_target()


@pytest.fixture
def submit(tenant, object_store, policy_profile):
    """Store an artifact and return a ready snapshot, bypassing the HTTP layer."""

    def factory(target, payload: bytes, source_type=SourceType.TERRAFORM_PLAN, **overrides):
        with tenant_context(tenant.id):
            snapshot = DeploymentSnapshot.objects.create(
                tenant=tenant,
                target=target,
                source_type=source_type,
                artifact_object_key="pending",
                artifact_sha256="0" * 64,
                artifact_size=len(payload),
                collected_by_type=DeploymentSnapshot.CollectorType.USER,
                collected_by_id="test",
                ingestion_state=DeploymentSnapshot.IngestionState.VALIDATING,
                **overrides,
            )
            from deployment_assurance.models import EvidenceArtifact
            from deployment_assurance.resources import sha256_hex

            artifact = evidence.record(
                tenant=tenant,
                target=target,
                snapshot=snapshot,
                role=EvidenceArtifact.Role.SOURCE_ARTIFACT,
                payload=payload,
                media_type="application/json",
                source={"type": "test"},
                run_id=str(snapshot.id),
            )
            snapshot.artifact_object_key = artifact.object_key
            snapshot.artifact_sha256 = sha256_hex(payload)
            snapshot.ingestion_state = DeploymentSnapshot.IngestionState.READY
            snapshot.finalized_at = timezone.now()
            snapshot.save(
                update_fields=[
                    "artifact_object_key",
                    "artifact_sha256",
                    "ingestion_state",
                    "finalized_at",
                    "updated_at",
                ]
            )
            return snapshot

    return factory


@pytest.fixture
def run_evaluation(tenant, policy_profile):
    """Create and synchronously execute an evaluation run."""

    def factory(snapshot, **overrides):
        with tenant_context(tenant.id):
            run = EvaluationRun.objects.create(
                tenant=tenant,
                snapshot=snapshot,
                target=snapshot.target,
                policy_pack=policy_profile.policy_pack,
                policy_profile=policy_profile,
                requested_by_type=DeploymentSnapshot.CollectorType.USER,
                requested_by_id="test",
                **overrides,
            )
            decision = evaluation.evaluate_snapshot(run)
            run.refresh_from_db()
            return run, decision

    return factory


def terraform_plan(*resources) -> bytes:
    """Build a minimal but structurally faithful Terraform plan document."""
    return json.dumps(
        {
            "format_version": "1.2",
            "terraform_version": "1.9.0",
            "resource_changes": [
                {
                    "address": address,
                    "type": resource_type,
                    "change": {"actions": ["create"], "after": after},
                }
                for address, resource_type, after in resources
            ],
        }
    ).encode()
