import socket
from types import SimpleNamespace

import httpx
import pytest

from core.ai_gateway import GatewayPolicyError, _credential_headers, invoke, redact, validate_endpoint


def test_redacts_common_secret_shapes():
    assert "hunter2" not in redact("password=hunter2")
    assert "AKIAABCDEFGHIJKLMNOP" not in redact("AKIAABCDEFGHIJKLMNOP")


def test_endpoint_requires_explicit_allowlist(monkeypatch):
    monkeypatch.setenv("AI_ENDPOINT_ALLOWLIST", "model.internal")
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]
    )
    validate_endpoint("https://model.internal")
    with pytest.raises(GatewayPolicyError):
        validate_endpoint("https://unapproved.internal")


def test_absent_credentials_fail_closed():
    with pytest.raises(GatewayPolicyError, match="Credential reference"):
        _credential_headers("")


def test_timeout_from_endpoint_is_bounded_and_propagated(monkeypatch):
    configuration = SimpleNamespace(
        endpoint_url="https://model.internal",
        endpoint_type="private_http",
        model_name="model",
        max_context_tokens=100,
        max_output_tokens=10,
        timeout_seconds=2,
        ca_bundle_path="",
        credential_reference="token",
    )

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["timeout"] == 2

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, *args, **kwargs):
            raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr("core.ai_gateway.validate_endpoint", lambda url: None)
    monkeypatch.setattr("core.ai_gateway._credential_headers", lambda reference: {})
    monkeypatch.setattr(httpx, "Client", Client)
    with pytest.raises(httpx.ReadTimeout):
        invoke(
            configuration=configuration,
            workflow="scan_enrichment",
            messages=[],
            response_schema={"type": "object"},
        )
