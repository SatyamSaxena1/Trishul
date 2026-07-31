import hashlib
import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import httpx
from jsonschema import validate

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
]


class GatewayPolicyError(ValueError):
    pass


def redact(value: str) -> str:
    for pattern in SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def validate_endpoint(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise GatewayPolicyError("AI endpoints must use an authenticated HTTPS authority.")
    allowlist = set(filter(None, os.getenv("AI_ENDPOINT_ALLOWLIST", "").split(",")))
    if parsed.hostname not in allowlist:
        raise GatewayPolicyError("AI endpoint hostname is not allowlisted.")
    denied = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("169.254.170.2")}
    for result in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM):
        address = ipaddress.ip_address(result[4][0])
        if (
            address in denied
            or address.is_link_local
            or address.is_loopback
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise GatewayPolicyError("AI endpoint resolves to a forbidden address.")


def _credential_headers(reference: str) -> dict:
    if not reference:
        raise GatewayPolicyError("Credential reference is unavailable.")
    base = Path("/run/secrets").resolve()
    target = (base / reference).resolve()
    if base not in target.parents or not target.is_file():
        raise GatewayPolicyError("Credential reference is unavailable.")
    value = target.read_text(encoding="utf-8").strip()
    return {"Authorization": f"Bearer {value}"}


def invoke(*, configuration, workflow: str, messages: list[dict], response_schema: dict) -> tuple[dict, dict]:
    validate_endpoint(configuration.endpoint_url)
    allowed_roles = {"system", "user", "assistant"}
    minimized = []
    for message in messages:
        if message.get("role") not in allowed_roles:
            raise GatewayPolicyError("Unsupported message role.")
        content = redact(str(message.get("content", "")))[:100_000]
        minimized.append({"role": message["role"], "content": content})
    if sum(len(message["content"]) for message in minimized) > configuration.max_context_tokens * 4:
        raise GatewayPolicyError("Minimized context exceeds the tenant model limit.")
    base_url = configuration.endpoint_url.rstrip("/")
    if configuration.endpoint_type == "openai_compatible":
        url = f"{base_url}/v1/chat/completions"
        payload = {
            "model": configuration.model_name,
            "messages": minimized,
            "response_format": {"type": "json_object"},
            "max_tokens": configuration.max_output_tokens,
        }
    else:
        url = f"{base_url}/invoke"
        payload = {
            "model": configuration.model_name,
            "workflow": workflow,
            "messages": minimized,
            "response_schema": response_schema,
            "max_output_tokens": configuration.max_output_tokens,
        }
    verify = configuration.ca_bundle_path or True
    with httpx.Client(timeout=configuration.timeout_seconds, verify=verify, follow_redirects=False) as session:
        response = session.post(url, json=payload, headers=_credential_headers(configuration.credential_reference))
        if 300 <= response.status_code < 400:
            raise GatewayPolicyError("AI endpoint redirects are forbidden.")
        response.raise_for_status()
        body = response.json()
    if configuration.endpoint_type == "openai_compatible":
        content = body["choices"][0]["message"]["content"]
        output = json.loads(content)
        usage = body.get("usage", {})
    else:
        output = body.get("output", body)
        usage = body.get("usage", {})
    validate(output, response_schema)
    metadata = {
        "request_hash": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
        "response_hash": hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest(),
        "input_tokens": int(usage.get("prompt_tokens", usage.get("input_tokens", 0))),
        "output_tokens": int(usage.get("completion_tokens", usage.get("output_tokens", 0))),
    }
    return output, metadata
