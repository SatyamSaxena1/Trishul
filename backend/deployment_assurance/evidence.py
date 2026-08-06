"""Evidence capture for deployment decisions.

A decision is only defensible if a third party can reconstruct it. Every input
and output of an evaluation is therefore written to the object store as an
immutable, hashed artifact with a provenance envelope, and indexed in
PostgreSQL.

On the strength of the guarantee, and its honest limit: a SHA-256 recorded
beside the object it describes proves the object has not changed *relative to a
hash you trust*. If an adversary can rewrite both the object and the database
row, the hash proves nothing. Detecting that class of tampering requires the
checkpoint to leave the system — see ``docs/operations.md`` for the exported
audit-checkpoint procedure. This module produces the hashes and envelopes that
make such a checkpoint meaningful; it does not, by itself, make storage
tamper-proof.
"""

import io
from typing import Any, Mapping

from django.conf import settings
from django.utils import timezone

from core.storage import put_file

from .limits import ArtifactTooLarge
from .models import EvidenceArtifact
from .resources import canonical_json, sha256_hex

ENVELOPE_SCHEMA_VERSION = "trishul-evidence-envelope/1.0"


def store_bytes(key: str, payload: bytes, *, content_type: str) -> None:
    """Write raw bytes to the object store.

    Indirected through this function so that tests and the offline normalizer
    CLI can substitute a backend without reaching into ``core.storage``.
    """
    put_file(key, io.BytesIO(payload), content_type=content_type)


def object_key(*, tenant_id, target_id, run_id: str, role: str, suffix: str) -> str:
    """Tenant-prefixed, unguessable object key.

    The tenant UUID leads the path so that a bucket policy or IAM condition can
    scope access per tenant without parsing the rest of the key.
    """
    return f"{tenant_id}/deployment-assurance/{target_id}/{run_id}/{role}{suffix}"


def build_envelope(
    *,
    tenant_id,
    target_id,
    role: str,
    object_key_value: str,
    media_type: str,
    payload: bytes,
    digest: str,
    source: Mapping[str, Any],
    evaluation_run_id=None,
    policy_pack_hash: str = "",
) -> dict:
    return {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "tenant_id": str(tenant_id),
        "target_id": str(target_id),
        "evaluation_run_id": str(evaluation_run_id) if evaluation_run_id else None,
        "role": role,
        "source": dict(source),
        "content": {
            "object_key": object_key_value,
            "media_type": media_type,
            "size_bytes": len(payload),
            "sha256": digest,
        },
        "collected_at": timezone.now().isoformat(),
        "classification": "confidential",
        "retention_class": settings.ASSURANCE_EVIDENCE_RETENTION_CLASS,
        "policy_pack_hash": policy_pack_hash,
    }


def record(
    *,
    tenant,
    target,
    role: str,
    payload: bytes,
    media_type: str,
    source: Mapping[str, Any],
    snapshot=None,
    evaluation_run=None,
    run_id: str | None = None,
    policy_pack_hash: str = "",
    max_bytes: int | None = None,
) -> EvidenceArtifact:
    """Store an artifact and index it as immutable evidence.

    Returns the created ``EvidenceArtifact``. Raises ``ArtifactTooLarge`` before
    any write when the payload exceeds the supplied bound.
    """
    if max_bytes is not None and len(payload) > max_bytes:
        raise ArtifactTooLarge(f"{role} artifact of {len(payload)} bytes exceeds the {max_bytes} byte bound.")
    digest = sha256_hex(payload)
    identifier = run_id or (str(evaluation_run.id) if evaluation_run else str(snapshot.id if snapshot else "adhoc"))
    suffix = ".json" if media_type == "application/json" else ".bin"
    key = object_key(tenant_id=tenant.id, target_id=target.id, run_id=identifier, role=role, suffix=suffix)
    envelope = build_envelope(
        tenant_id=tenant.id,
        target_id=target.id,
        role=role,
        object_key_value=key,
        media_type=media_type,
        payload=payload,
        digest=digest,
        source=source,
        evaluation_run_id=evaluation_run.id if evaluation_run else None,
        policy_pack_hash=policy_pack_hash,
    )
    store_bytes(key, payload, content_type=media_type)
    return EvidenceArtifact.all_objects.create(
        tenant=tenant,
        target=target,
        snapshot=snapshot,
        evaluation_run=evaluation_run,
        role=role,
        object_key=key,
        media_type=media_type,
        size_bytes=len(payload),
        sha256=digest,
        envelope=envelope,
        retention_class=settings.ASSURANCE_EVIDENCE_RETENTION_CLASS,
    )


def record_json(*, document: Any, **kwargs) -> EvidenceArtifact:
    """Store a canonically serialized JSON document as evidence."""
    return record(payload=canonical_json(document), media_type="application/json", **kwargs)
