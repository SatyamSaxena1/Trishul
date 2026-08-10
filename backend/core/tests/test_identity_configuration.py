from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import override_settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIClient

from core.models import AuthSession, IdentityProviderConfiguration, Membership, Tenant, TenantSessionPolicy
from core.security import OIDCBearerAuthentication
from core.tenancy import tenant_context

pytestmark = pytest.mark.django_db


def _member(tenant, username):
    user = get_user_model().objects.create(username=username)
    Membership.all_objects.create(tenant=tenant, user=user, role=Membership.Role.ORG_ADMIN)
    return user


def _oidc(tenant, **overrides):
    values = {
        "tenant": tenant,
        "protocol": "oidc",
        "name": "Enterprise identity",
        "issuer": "https://identity.example.test",
        "client_id": "trishul",
        "audience": "trishul-api",
        "jwks_url": "https://identity.example.test/keys",
        "secret_reference": "secret/identity/client",
        "enabled": True,
    }
    values.update(overrides)
    return IdentityProviderConfiguration.all_objects.create(**values)


def test_identity_configuration_is_tenant_scoped_and_hides_secret_reference():
    first = Tenant.objects.create(slug="identity-a", name="Identity A")
    second = Tenant.objects.create(slug="identity-b", name="Identity B")
    first_user = _member(first, "identity-admin-a")
    second_user = _member(second, "identity-admin-b")
    _oidc(first)

    client = APIClient()
    client.force_authenticate(first_user)
    own = client.get("/api/v1/identity-providers/")
    assert own.status_code == 200
    assert len(own.data["results"]) == 1
    assert "secret_reference" not in own.data["results"][0]
    client.force_authenticate(second_user)
    assert client.get("/api/v1/identity-providers/").data["results"] == []

    public = APIClient().get("/api/v1/auth/config?tenant_slug=identity-a")
    assert public.data["protocol"] == "oidc"
    assert public.data["authority"] == "https://identity.example.test"
    assert public.data["client_id"] == "trishul"


@patch("core.views.socket.getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))])
@patch("core.views.httpx.get")
def test_provider_validation_checks_remote_metadata(mock_get, _resolve):
    tenant = Tenant.objects.create(slug="identity-validation", name="Identity validation")
    user = _member(tenant, "identity-validator")
    configuration = _oidc(tenant)
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "issuer": configuration.issuer,
        "jwks_uri": configuration.jwks_url,
        "authorization_endpoint": "https://identity.example.test/authorize",
        "token_endpoint": "https://identity.example.test/token",
    }
    mock_get.return_value = response
    client = APIClient()
    client.force_authenticate(user)

    result = client.post(f"/api/v1/identity-providers/{configuration.id}/validate/")

    assert result.status_code == 200, result.data
    configuration.refresh_from_db()
    assert configuration.validated_at is not None


@patch("core.security.jwt.decode")
@patch("core.security.jwt.PyJWKClient")
def test_tenant_oidc_token_cannot_select_another_membership(jwks_client, decode):
    first = Tenant.objects.create(slug="token-a", name="Token A")
    second = Tenant.objects.create(slug="token-b", name="Token B")
    user = get_user_model().objects.create(username="shared-subject")
    Membership.all_objects.create(tenant=first, user=user, role=Membership.Role.ORG_ADMIN)
    Membership.all_objects.create(tenant=second, user=user, role=Membership.Role.ORG_ADMIN)
    _oidc(first)
    claims = {
        "sub": user.username,
        "iss": "https://identity.example.test",
        "aud": "trishul-api",
        "exp": 2_000_000_000,
        "iat": 1_900_000_000,
        "amr": ["mfa"],
    }
    decode.side_effect = [claims.copy(), claims.copy()]
    jwks_client.return_value.get_signing_key_from_jwt.return_value.key = "key"
    OIDCBearerAuthentication._jwks_clients = {}

    response = APIClient().get(
        "/api/v1/context",
        HTTP_AUTHORIZATION="Bearer signed-token",
        HTTP_X_TRISHUL_TENANT=str(second.id),
    )

    assert response.status_code == 403
    assert "OIDC is not configured" in str(response.data), response.data


def test_identity_and_session_configuration_fail_closed():
    tenant = Tenant.objects.create(slug="identity-guards", name="Identity guards")
    with pytest.raises(ValidationError, match="requires client_id"):
        _oidc(tenant, client_id="")
    with tenant_context(tenant.id), pytest.raises(ValidationError, match="Idle timeout"):
        TenantSessionPolicy.objects.create(tenant=tenant, idle_timeout_minutes=61, absolute_timeout_minutes=60)
    with override_settings(DEBUG=False), pytest.raises(ValidationError, match="HTTPS"):
        _oidc(
            tenant,
            issuer="http://identity.example.test",
            jwks_url="http://identity.example.test/keys",
        )


def test_session_policy_revokes_the_oldest_concurrent_token():
    tenant = Tenant.objects.create(slug="session-limit", name="Session limit")
    user = _member(tenant, "session-user")
    configuration = _oidc(tenant)
    with tenant_context(tenant.id):
        TenantSessionPolicy.objects.create(tenant=tenant, max_concurrent_sessions=1)
        first = OIDCBearerAuthentication._enforce_session(
            configuration, user, "first-token", {"exp": 2_000_000_000}
        )
        second = OIDCBearerAuthentication._enforce_session(
            configuration, user, "second-token", {"exp": 2_000_000_000}
        )
    first.refresh_from_db()
    assert first.revoked_at is not None
    assert second.revoked_at is None


def test_idle_session_is_rejected():
    tenant = Tenant.objects.create(slug="session-idle", name="Session idle")
    user = _member(tenant, "idle-user")
    configuration = _oidc(tenant)
    with tenant_context(tenant.id):
        TenantSessionPolicy.objects.create(tenant=tenant, idle_timeout_minutes=1)
        session = OIDCBearerAuthentication._enforce_session(
            configuration, user, "idle-token", {"exp": 2_000_000_000}
        )
        AuthSession.objects.filter(pk=session.pk).update(last_seen_at=timezone.now() - timedelta(minutes=2))
        with pytest.raises(AuthenticationFailed, match="expired or been revoked"):
            OIDCBearerAuthentication._enforce_session(
                configuration, user, "idle-token", {"exp": 2_000_000_000}
            )


def test_user_can_list_and_revoke_only_their_own_sessions():
    tenant = Tenant.objects.create(slug="session-api", name="Session API")
    user = _member(tenant, "session-api-user")
    other = _member(tenant, "session-api-other")
    configuration = _oidc(tenant)
    with tenant_context(tenant.id):
        own = OIDCBearerAuthentication._enforce_session(
            configuration, user, "own-token", {"exp": 2_000_000_000}
        )
        OIDCBearerAuthentication._enforce_session(
            configuration, other, "other-token", {"exp": 2_000_000_000}
        )
    client = APIClient()
    client.force_authenticate(user)
    response = client.get("/api/v1/sessions/", HTTP_X_TRISHUL_TENANT=str(tenant.id))
    assert response.status_code == 200
    assert [item["id"] for item in response.data["results"]] == [str(own.id)]
    revoked = client.post(f"/api/v1/sessions/{own.id}/revoke/", HTTP_X_TRISHUL_TENANT=str(tenant.id))
    assert revoked.status_code == 204
    own.refresh_from_db()
    assert own.revoked_at is not None
