"""Normalized inventory normalizer.

The ingestion path for anything that is already structured: a server inventory
agent, an OpenSCAP or InSpec export converted by a collector, a vulnerability
scanner report, or a cloud connector's own output. Rather than teaching Trishul
every vendor schema, the collector emits this envelope:

.. code-block:: json

    {
      "schema_version": "trishul-inventory/1.0",
      "provider": "on_prem",
      "hosts": [{"host_id": "web-01", "os_name": "ubuntu", "os_version": "20.04"}],
      "vulnerabilities": [{"id": "V-1", "cve": "CVE-2024-0001", "cvss": 9.8,
                           "asset_id": "web-01", "exploit_known": true}],
      "resources": [ ... canonical resources, passed through unchanged ... ]
    }

The ``resources`` array is the escape hatch: a connector that already speaks the
canonical envelope can submit it directly, which is how live cloud collection
will attach without a schema change.
"""

from typing import Iterator, Mapping

from ..limits import UnsafeArtifact
from ..resources import Resource, ResourceType, normalized_document
from .safeload import load_json

INVENTORY_SCHEMA_VERSION = "trishul-inventory/1.0"


def _hosts(entries) -> Iterator[Resource]:
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        host_id = str(entry.get("host_id") or entry.get("hostname") or "")
        if not host_id:
            continue
        yield Resource(
            resource_type=ResourceType.OS_HOST,
            resource_id=host_id,
            provider=str(entry.get("provider") or "on_prem"),
            name=str(entry.get("hostname") or host_id),
            source_path=f"hosts.{host_id}",
            labels={str(k): str(v) for k, v in (entry.get("labels") or {}).items()},
            attributes={
                "os_name": str(entry.get("os_name") or "").lower(),
                "os_version": str(entry.get("os_version") or ""),
                "kernel_version": str(entry.get("kernel_version") or ""),
                "patched_at": str(entry.get("patched_at") or ""),
                "disk_encrypted": bool(entry.get("disk_encrypted")),
                "endpoint_agent_present": bool(entry.get("endpoint_agent_present")),
            },
        )


def _vulnerabilities(entries) -> Iterator[Resource]:
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        identifier = str(entry.get("id") or entry.get("cve") or "")
        asset_id = str(entry.get("asset_id") or "")
        if not identifier:
            continue
        try:
            cvss = float(entry.get("cvss") or 0.0)
        except (TypeError, ValueError):
            cvss = 0.0
        yield Resource(
            resource_type=ResourceType.VULNERABILITY,
            resource_id=f"{asset_id}::{identifier}" if asset_id else identifier,
            provider=str(entry.get("provider") or "generic"),
            name=str(entry.get("cve") or identifier),
            source_path=f"vulnerabilities.{identifier}",
            attributes={
                "cve": str(entry.get("cve") or ""),
                # CVSS is retained as the vendor-reported vulnerability severity.
                # It is an input to Trishul's risk model, never the final score.
                "cvss": cvss,
                "severity": str(entry.get("severity") or "").lower(),
                "asset_id": asset_id,
                "exploit_known": bool(entry.get("exploit_known")),
                "fix_available": bool(entry.get("fix_available")),
                "first_seen": str(entry.get("first_seen") or ""),
            },
        )


def _passthrough(entries) -> Iterator[Resource]:
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        resource_type = str(entry.get("resource_type") or "")
        if resource_type not in ResourceType.ALL:
            raise UnsafeArtifact(f"Unknown canonical resource_type {resource_type!r} in inventory.")
        if not entry.get("resource_id"):
            raise UnsafeArtifact("Every canonical resource requires a resource_id.")
        yield Resource.from_dict(entry)


def normalize(payload: bytes, *, provider: str = "on_prem") -> dict:
    document = load_json(payload)
    if not isinstance(document, Mapping):
        raise UnsafeArtifact("An inventory artifact must be a JSON object.")
    version = str(document.get("schema_version") or "")
    if version != INVENTORY_SCHEMA_VERSION:
        raise UnsafeArtifact(
            f"Unsupported inventory schema_version {version!r}; expected {INVENTORY_SCHEMA_VERSION!r}."
        )

    resources = [
        *_hosts(document.get("hosts") or ()),
        *_vulnerabilities(document.get("vulnerabilities") or ()),
        *_passthrough(document.get("resources") or ()),
    ]
    declared_provider = str(document.get("provider") or provider)
    return normalized_document(
        provider=declared_provider,
        source_type="server_inventory",
        resources=resources,
        metadata={
            "collector": str(document.get("collector") or ""),
            "collected_at": str(document.get("collected_at") or ""),
            "normalizer": "inventory",
        },
    )
