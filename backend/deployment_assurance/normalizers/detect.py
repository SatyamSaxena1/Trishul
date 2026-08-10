"""Plaintext-secret detection over normalized attribute trees.

A secret found inside a deployment artifact is a finding, but the secret itself
must never enter the evidence store, the audit log or an API response — that
would turn a compliance record into a credential leak. Detection therefore
emits the *location* and a salted-free SHA-256 digest of the value, never the
value. The digest lets an operator confirm a rotation actually changed the
material without ever revealing it.
"""

import hashlib
import re
from typing import Any, Iterator, Mapping

from ..resources import Resource, ResourceType

# Key names that carry credential material by convention.
SENSITIVE_KEY = re.compile(
    r"(?:^|[_.-])(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential"
    r"|client[_-]?secret|connection[_-]?string)(?:$|[_.-])",
    re.IGNORECASE,
)

# High-signal value shapes, checked regardless of key name.
VALUE_SIGNATURES = (
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abps]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)

# Values that look sensitive by key name but are references, not material.
REFERENCE_PATTERN = re.compile(
    r"^\s*(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|/run/secrets/\S*|file:\S*|arn:aws:secretsmanager:\S*"
    r"|projects/\S+/secrets/\S*|vault:\S*|secretKeyRef|valueFrom)\s*$"
)

MIN_MATERIAL_LENGTH = 8
PLACEHOLDERS = frozenset(
    {"", "changeme", "change_me", "placeholder", "example", "redacted", "null", "none", "todo", "xxx", "***"}
)


def _is_material(value: str) -> bool:
    """Whether a string looks like real credential material.

    Deliberately conservative: references, obvious placeholders and short
    values are excluded so the rule does not drown teams in false positives.
    """
    stripped = value.strip()
    if len(stripped) < MIN_MATERIAL_LENGTH:
        return False
    if stripped.lower() in PLACEHOLDERS:
        return False
    return not REFERENCE_PATTERN.match(stripped)


def _walk(value: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def find_secrets(tree: Any, *, source_path: str, owner_id: str, provider: str = "generic") -> list[Resource]:
    """Emit a ``secret.material`` resource for each plaintext secret found.

    The emitted attributes carry the detection reason, the attribute path and a
    digest — never the matched text.
    """
    found: list[Resource] = []
    for path, value in _walk(tree, ""):
        reasons = [name for name, pattern in VALUE_SIGNATURES if pattern.search(value)]
        leaf = path.rsplit(".", 1)[-1]
        if not reasons and SENSITIVE_KEY.search(leaf) and _is_material(value):
            reasons = ["sensitive_key_with_literal_value"]
        if not reasons:
            continue
        found.append(
            Resource(
                resource_type=ResourceType.SECRET_MATERIAL,
                resource_id=f"{owner_id}::{path}",
                provider=provider,
                name=leaf,
                source_path=source_path,
                attributes={
                    "attribute_path": path,
                    "detection_reasons": sorted(reasons),
                    # Digest only. The matched value never leaves this function.
                    "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    "value_length": len(value),
                },
            )
        )
    return found
