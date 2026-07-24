import ipaddress
import re
import socket
from urllib.parse import urlparse

from rest_framework import serializers

COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")


def validate_commit(value: str) -> str:
    value = value.lower()
    if not COMMIT_RE.fullmatch(value):
        raise serializers.ValidationError("Commit SHA must contain 40 to 64 hexadecimal characters.")
    return value


def validate_clone_url(provider: str, value: str) -> str:
    parsed = urlparse(value)
    hosts = {"github": {"github.com"}, "gitlab": {"gitlab.com"}}.get(provider, set())
    if parsed.scheme != "https" or parsed.hostname not in hosts or parsed.username or parsed.password:
        raise serializers.ValidationError(f"{provider.title()} clone URL must use HTTPS on an approved host.")
    return value


def validate_staging_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise serializers.ValidationError("Staging targets must use HTTPS without embedded credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise serializers.ValidationError("Register the staging origin, not an individual path.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443)}
    except socket.gaierror as exc:
        raise serializers.ValidationError("Staging target hostname does not resolve.") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise serializers.ValidationError("Staging target resolves to a forbidden address.")
    return value.rstrip("/")
