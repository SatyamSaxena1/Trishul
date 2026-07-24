import hashlib
import hmac
import json
from datetime import timedelta
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from core.credentials import decrypt_credential, encrypt_credential, encrypt_secret
from core.models import (
    Application,
    Finding,
    FindingEvidence,
    Organization,
    Repository,
    RepositoryVersion,
    ServiceAccount,
    StagingTarget,
    Tenant,
    WebhookDelivery,
    Workspace,
)
from core.serializers import RepositorySerializer
from core.tenancy import tenant_context


def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def application(tenant):
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name="Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name="Workspace")
        return Application.objects.create(tenant=tenant, workspace=workspace, name="App")


def service_token(tenant):
    _, token = ServiceAccount.issue(
        tenant=tenant,
        name="ci",
        scopes=["repository.read", "repository.import", "scan.read"],
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return token


def integration_settings():
    public, private = keys()
    return override_settings(
        INTEGRATION_SECRET_KEY=Fernet.generate_key().decode(),
        GIT_CREDENTIAL_PUBLIC_KEY=public,
        GIT_CREDENTIAL_PRIVATE_KEY=private,
    )


def test_git_credentials_use_asymmetric_encryption():
    with integration_settings():
        ciphertext = encrypt_credential("read-only-token")
        assert "read-only-token" not in ciphertext
        assert decrypt_credential(ciphertext) == "read-only-token"


@pytest.mark.django_db
def test_repository_serializer_encrypts_and_hides_integration_secrets():
    tenant = Tenant.objects.create(slug="tenant", name="Tenant")
    app = application(tenant)
    with integration_settings(), tenant_context(tenant.id):
        serializer = RepositorySerializer(
            data={
                "application": str(app.id),
                "name": "gitlab",
                "source_type": "gitlab",
                "clone_url": "https://gitlab.com/example/repo.git",
                "external_id": "42",
                "credential": "read-token",
                "webhook_secret": "hook-secret",
                "ci_secret": "ci-secret",
            }
        )
        assert serializer.is_valid(), serializer.errors
        repository = serializer.save(tenant=tenant)
        assert decrypt_credential(repository.credential_ciphertext) == "read-token"
        assert not any(name.endswith("_ciphertext") for name in serializer.data)


@pytest.mark.django_db
def test_signed_zap_results_are_advisory_and_evidence_backed():
    tenant = Tenant.objects.create(slug="tenant", name="Tenant")
    app = application(tenant)
    commit = "a" * 40
    with integration_settings(), tenant_context(tenant.id):
        repository = Repository.objects.create(
            tenant=tenant,
            application=app,
            name="repo",
            ci_secret_ciphertext=encrypt_secret("ci-secret"),
        )
        version = RepositoryVersion.objects.create(
            tenant=tenant,
            repository=repository,
            object_key="source.tar",
            sha256="b" * 64,
            size=1,
            commit_sha=commit,
            manifest={"files": []},
        )
        StagingTarget.objects.create(tenant=tenant, application=app, url="https://staging.example.com", approved=True)
        token = service_token(tenant)
        bundle = {
            "schema": "trishul-ci-results-v1",
            "commit_sha": commit,
            "pack": "zap",
            "pack_version": "2.16",
            "coverage": {
                "target": "https://staging.example.com",
                "authenticated": False,
                "requests_per_second": 5,
                "duration_seconds": 60,
            },
            "findings": [
                {
                    "rule_id": "ZAP-10001",
                    "rule_version": "2.16",
                    "title": "Missing security header",
                    "description": "A response header is absent.",
                    "severity": 3,
                    "confidence": 4,
                    "fingerprint": hashlib.sha256(b"zap").hexdigest(),
                    "evidence": [
                        {
                            "evidence_type": "http",
                            "location": {
                                "url": "https://staging.example.com/login",
                                "method": "GET",
                                "zap_rule": "10001",
                            },
                        }
                    ],
                }
            ],
        }
        body = json.dumps(bundle, separators=(",", ":")).encode()
        signature = "sha256=" + hmac.new(b"ci-secret", body, hashlib.sha256).hexdigest()
        with patch("core.views.put_file"):
            response = APIClient().post(
                f"/api/v1/repository-versions/{version.id}/external-results/",
                body,
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {token}",
                HTTP_X_TRISHUL_SIGNATURE_256=signature,
            )
            rejected_bundle = {**bundle, "coverage": {**bundle["coverage"], "target": "https://production.example.com"}}
            rejected_body = json.dumps(rejected_bundle, separators=(",", ":")).encode()
            rejected = APIClient().post(
                f"/api/v1/repository-versions/{version.id}/external-results/",
                rejected_body,
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {token}",
                HTTP_X_TRISHUL_SIGNATURE_256=(
                    "sha256=" + hmac.new(b"ci-secret", rejected_body, hashlib.sha256).hexdigest()
                ),
            )
        assert response.status_code == 201
        assert rejected.status_code == 400
        finding = Finding.all_objects.get(scan_id=response.json()["id"])
        assert finding.status == Finding.Status.NEEDS_VALIDATION
        assert FindingEvidence.all_objects.get(finding=finding).evidence_type == FindingEvidence.Type.HTTP


@pytest.mark.django_db(transaction=True)
def test_gitlab_webhook_is_verified_and_replay_safe():
    tenant = Tenant.objects.create(slug="tenant", name="Tenant")
    app = application(tenant)
    commit = "c" * 40
    with integration_settings(), tenant_context(tenant.id):
        repository = Repository.objects.create(
            tenant=tenant,
            application=app,
            name="gitlab",
            source_type=Repository.SourceType.GITLAB,
            clone_url="https://gitlab.com/example/repo.git",
            external_id="42",
            credential_ciphertext=encrypt_credential("read-token"),
            webhook_secret_ciphertext=encrypt_secret("hook-secret"),
        )
        payload = json.dumps({"project": {"id": 42}, "after": commit, "checkout_sha": commit, "ref": "refs/heads/main"})
        url = f"/api/v1/webhooks/gitlab/{tenant.id}/{repository.id}"
        headers = {
            "content_type": "application/json",
            "HTTP_X_GITLAB_TOKEN": "hook-secret",
            "HTTP_X_GITLAB_EVENT": "Push Hook",
            "HTTP_X_GITLAB_EVENT_UUID": "delivery-1",
        }
        with patch("core.tasks.fetch_repository.apply_async") as enqueue:
            rejected = APIClient().post(url, payload, **{**headers, "HTTP_X_GITLAB_TOKEN": "wrong"})
            first = APIClient().post(url, payload, **headers)
            second = APIClient().post(url, payload, **headers)
        assert rejected.status_code == 403
        assert first.status_code == second.status_code == 202
        assert first.json()["state"] == "queued"
        assert second.json()["state"] == "duplicate"
        assert WebhookDelivery.all_objects.count() == 1
        enqueue.assert_called_once()
