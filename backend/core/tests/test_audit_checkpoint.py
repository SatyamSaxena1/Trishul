import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError
from django.core.management import call_command
from django.core.management.base import CommandError

from core.audit import canonical_json, checkpoint_document
from core.models import AuditEvent, Tenant


def append_event(tenant, action):
    return AuditEvent.append(
        tenant=tenant,
        actor_type="system",
        actor_id="checkpoint-test",
        action=action,
        resource_type="tenant",
        resource_id=tenant.id,
        details={"test": True},
    )


@pytest.mark.django_db
@patch("core.management.commands.publish_audit_checkpoint.boto3.client")
@patch("core.management.commands.publish_audit_checkpoint.timezone.now")
def test_publish_checkpoint_is_canonical_and_emits_success_metric(mock_now, mock_client, settings, capsys):
    created_at = datetime(2026, 8, 6, 12, 30, tzinfo=timezone.utc)
    mock_now.return_value = created_at
    tenant = Tenant.objects.create(slug="checkpoint", name="Checkpoint")
    event = append_event(tenant, "checkpoint.test")
    s3 = Mock()
    cloudwatch = Mock()
    mock_client.side_effect = [s3, cloudwatch]
    settings.S3_REGION = "ap-south-1"
    settings.AUDIT_CHECKPOINT_BUCKET = "security-audit-checkpoints"
    settings.AUDIT_CHECKPOINT_PREFIX = "audit-checkpoints"

    call_command("publish_audit_checkpoint")

    request = s3.put_object.call_args.kwargs
    expected = canonical_json(checkpoint_document(created_at))
    assert request["Body"] == expected
    assert json.loads(expected)["tenant_heads"] == [
        {"tenant_id": str(tenant.id), "last_audit_hash": event.event_hash}
    ]
    assert request["Metadata"] == {"sha256": hashlib.sha256(expected).hexdigest()}
    assert request["Key"].endswith("/2026/08/06/20260806T123000000000Z.json")
    cloudwatch.put_metric_data.assert_called_once()
    assert "sha256=" in capsys.readouterr().out


@pytest.mark.django_db
@patch("core.management.commands.publish_audit_checkpoint.boto3.client")
def test_publish_checkpoint_fails_closed_on_upload_error(mock_client, settings):
    settings.AUDIT_CHECKPOINT_BUCKET = "security-audit-checkpoints"
    settings.AUDIT_CHECKPOINT_PREFIX = "audit-checkpoints"
    mock_client.return_value.put_object.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "PutObject"
    )
    with pytest.raises(CommandError, match="publication failed"):
        call_command("publish_audit_checkpoint")


@pytest.mark.django_db
def test_verify_accepts_checkpoint_head_as_chain_ancestor_and_rejects_tampering(tmp_path):
    tenant = Tenant.objects.create(slug="verify", name="Verify")
    trusted = append_event(tenant, "first")
    checkpoint = checkpoint_document(datetime(2026, 8, 6, 12, 30, tzinfo=timezone.utc))
    path = tmp_path / "checkpoint.json"
    path.write_bytes(canonical_json(checkpoint))
    append_event(tenant, "second")

    call_command("verify_audit", checkpoint=str(path))

    checkpoint["tenant_heads"][0]["last_audit_hash"] = "f" * 64
    path.write_bytes(canonical_json(checkpoint))
    with pytest.raises(CommandError, match="not in the chain"):
        call_command("verify_audit", checkpoint=str(path))
    assert trusted.event_hash != "f" * 64
