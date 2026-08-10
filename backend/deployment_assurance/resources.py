"""The canonical resource envelope.

Every provider and artifact format is reduced to this one shape before any rule
runs. That is what lets a rule be written once and applied to a Terraform plan,
a Kubernetes manifest and a live cloud inventory alike.

Two properties matter and are enforced here rather than left to convention:

* **Determinism.** ``canonical_json`` emits sorted keys and compact separators,
  and ``normalized_document`` sorts resources by ``(resource_type,
  resource_id)``. The same input therefore always hashes to the same digest.
* **Boundedness.** Attribute values are truncated and collections capped, so a
  hostile artifact cannot inflate memory or the evidence store.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .limits import (
    MAX_COLLECTION_ITEMS,
    MAX_DOCUMENT_DEPTH,
    MAX_RESOURCES,
    MAX_STRING_CHARS,
    UnsafeArtifact,
)

SCHEMA_VERSION = "trishul-resource/1.0"
DOCUMENT_SCHEMA_VERSION = "trishul-normalized-snapshot/1.0"


class ResourceType:
    """The canonical resource taxonomy.

    Rules declare the types they understand. A resource whose type no rule
    claims is reported as ``not_evaluated`` rather than silently passing.
    """

    INGRESS_RULE = "network.ingress_rule"
    TLS_ENDPOINT = "network.tls_endpoint"
    COMPUTE_INSTANCE = "compute.instance"
    CONTAINER = "compute.container"
    STORAGE_BUCKET = "storage.bucket"
    STORAGE_VOLUME = "storage.volume"
    DATABASE_INSTANCE = "database.instance"
    IDENTITY_POLICY = "identity.policy"
    LOGGING_SINK = "logging.sink"
    BACKUP_PLAN = "backup.plan"
    # A resource *type* naming the finding category. No credential is stored on
    # this resource — only a location and a digest. See `normalizers.detect`.
    SECRET_MATERIAL = "secret.material"  # noqa: S105
    OS_HOST = "os.host"
    VULNERABILITY = "vulnerability.finding"

    ALL = frozenset(
        {
            INGRESS_RULE,
            TLS_ENDPOINT,
            COMPUTE_INSTANCE,
            CONTAINER,
            STORAGE_BUCKET,
            STORAGE_VOLUME,
            DATABASE_INSTANCE,
            IDENTITY_POLICY,
            LOGGING_SINK,
            BACKUP_PLAN,
            SECRET_MATERIAL,
            OS_HOST,
            VULNERABILITY,
        }
    )


@dataclass(frozen=True)
class Resource:
    """One normalized resource. Rules receive these and never raw artifacts."""

    resource_type: str
    resource_id: str
    provider: str = "generic"
    name: str = ""
    source_path: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    relationships: Sequence[Mapping[str, str]] = field(default_factory=tuple)
    labels: Mapping[str, str] = field(default_factory=dict)

    def attribute(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)

    def as_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "provider": self.provider,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "name": self.name,
            "source_path": self.source_path,
            "labels": dict(sorted(self.labels.items())),
            "attributes": _bounded(self.attributes),
            "relationships": [dict(sorted(item.items())) for item in self.relationships],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Resource":
        return cls(
            resource_type=str(payload["resource_type"]),
            resource_id=str(payload["resource_id"]),
            provider=str(payload.get("provider", "generic")),
            name=str(payload.get("name", "")),
            source_path=str(payload.get("source_path", "")),
            attributes=dict(payload.get("attributes") or {}),
            relationships=tuple(dict(item) for item in payload.get("relationships") or ()),
            labels=dict(payload.get("labels") or {}),
        )


def _bounded(value: Any, depth: int = 0) -> Any:
    """Truncate strings and cap collections so evidence stays bounded.

    Truncation is marked with a trailing ellipsis rather than being silent, so a
    reader can tell that a value was shortened.
    """
    if depth > MAX_DOCUMENT_DEPTH:
        raise UnsafeArtifact("Attribute nesting exceeds the permitted depth.")
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING_CHARS else value[:MAX_STRING_CHARS] + "…"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda pair: str(pair[0]))[:MAX_COLLECTION_ITEMS]
        return {str(key): _bounded(item, depth + 1) for key, item in items}
    if isinstance(value, (list, tuple, set, frozenset)):
        ordered = list(value)[:MAX_COLLECTION_ITEMS]
        return [_bounded(item, depth + 1) for item in ordered]
    return _bounded(str(value), depth + 1)


def canonical_json(payload: Any) -> bytes:
    """Serialize deterministically. The only serializer used for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_document(
    *, provider: str, source_type: str, resources: Iterable[Resource], metadata: Mapping[str, Any] | None = None
) -> dict:
    """Build the canonical normalized snapshot document.

    Resources are sorted and de-duplicated by ``(resource_type, resource_id)``
    so that artifact ordering never changes the digest. A duplicate identifier
    is a normalizer defect, so the first occurrence wins and the count of
    discarded duplicates is recorded in metadata rather than hidden.
    """
    seen: dict[tuple[str, str], Resource] = {}
    duplicates = 0
    for resource in resources:
        key = (resource.resource_type, resource.resource_id)
        if key in seen:
            duplicates += 1
            continue
        seen[key] = resource
        if len(seen) > MAX_RESOURCES:
            raise UnsafeArtifact(f"Artifact declares more than {MAX_RESOURCES} resources.")
    ordered = [seen[key].as_dict() for key in sorted(seen)]
    document_metadata = dict(metadata or {})
    if duplicates:
        document_metadata["duplicate_resource_ids_discarded"] = duplicates
    return {
        "schema_version": DOCUMENT_SCHEMA_VERSION,
        "provider": provider,
        "source_type": source_type,
        "resource_count": len(ordered),
        "metadata": _bounded(document_metadata),
        "resources": ordered,
    }


def load_resources(document: Mapping[str, Any]) -> list[Resource]:
    """Rehydrate resources from a stored normalized document."""
    if document.get("schema_version") != DOCUMENT_SCHEMA_VERSION:
        raise UnsafeArtifact(f"Unsupported normalized schema: {document.get('schema_version')!r}")
    return [Resource.from_dict(item) for item in document.get("resources", ())]
