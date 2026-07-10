import socket

import pytest

from core.ai_gateway import GatewayPolicyError, redact, validate_endpoint


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
