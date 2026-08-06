import json
import re
from datetime import datetime
from pathlib import Path
from uuid import UUID

from django.utils import timezone

from core.models import AuditEvent, Tenant
from core.tenancy import database_tenant_context

CHECKPOINT_FORMAT = "ai-trishul-audit-checkpoint-v1"


def latest_audit_heads():
    heads = []
    for tenant_id in Tenant.objects.order_by("id").values_list("id", flat=True).iterator():
        with database_tenant_context(tenant_id):
            event_hash = AuditEvent.objects.order_by("-occurred_at", "-id").values_list("event_hash", flat=True).first()
        heads.append({"tenant_id": str(tenant_id), "last_audit_hash": event_hash or ""})
    return heads


def checkpoint_document(created_at=None):
    return {
        "format": CHECKPOINT_FORMAT,
        "created_at": (created_at or timezone.now()).isoformat(),
        "tenant_heads": latest_audit_heads(),
    }


def canonical_json(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def load_checkpoint(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("format") != CHECKPOINT_FORMAT:
        raise ValueError("Unsupported audit checkpoint format")
    created_at = document.get("created_at")
    if not isinstance(created_at, str) or datetime.fromisoformat(created_at.replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("Audit checkpoint created_at must include a timezone")
    heads = document.get("tenant_heads")
    if not isinstance(heads, list):
        raise ValueError("Audit checkpoint tenant_heads must be a list")
    result = {}
    for item in heads:
        if not isinstance(item, dict) or set(item) != {"tenant_id", "last_audit_hash"}:
            raise ValueError("Invalid audit checkpoint tenant head")
        tenant_id = str(UUID(item["tenant_id"]))
        event_hash = item["last_audit_hash"]
        if not isinstance(event_hash, str) or (event_hash and not re.fullmatch(r"[0-9a-f]{64}", event_hash)):
            raise ValueError("Invalid audit checkpoint hash")
        if tenant_id in result:
            raise ValueError("Duplicate audit checkpoint tenant")
        result[tenant_id] = event_hash
    return result
