from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import override_settings
from rest_framework.test import APIClient

from core.models import IdentityProviderConfiguration, Membership, Tenant, TenantSessionPolicy
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
    assert any("does not authorize" in str(value) for value in response.data.values()), response.data


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
