"""Artifact normalizers.

Each normalizer turns one artifact format into the canonical resource envelope
defined in ``deployment_assurance.resources``. Normalizers are pure functions
over bytes: they perform no network access, read no credentials and touch no
database. They run inside the isolated analyzer job through ``normalizers.cli``.
"""

from ..limits import UnsafeArtifact
from . import compose, inventory, kubernetes, terraform

NORMALIZER_VERSION = "1.0.0"

_NORMALIZERS = {
    "terraform_plan": terraform.normalize,
    "kubernetes_manifest": kubernetes.normalize,
    "compose_file": compose.normalize,
    "server_inventory": inventory.normalize,
    "cloud_inventory": inventory.normalize,
}

SUPPORTED_SOURCE_TYPES = frozenset(_NORMALIZERS)


def normalize(*, source_type: str, payload: bytes, provider: str = "generic") -> dict:
    """Normalize an artifact into a canonical snapshot document.

    Raises ``UnsafeArtifact`` for malformed or out-of-bounds input; callers
    translate that into a rejected snapshot rather than an approved one.
    """
    handler = _NORMALIZERS.get(source_type)
    if handler is None:
        raise UnsafeArtifact(f"No normalizer is registered for source type {source_type!r}.")
    document = handler(payload, provider=provider)
    document["source_type"] = source_type
    return document


__all__ = ["NORMALIZER_VERSION", "SUPPORTED_SOURCE_TYPES", "normalize"]
