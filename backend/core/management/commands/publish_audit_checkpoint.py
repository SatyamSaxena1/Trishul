import hashlib
import re

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.audit import canonical_json, checkpoint_document


class Command(BaseCommand):
    help = "Publish current tenant audit heads to immutable object storage."

    def handle(self, **options):
        if not settings.AUDIT_CHECKPOINT_BUCKET:
            raise CommandError("AUDIT_CHECKPOINT_BUCKET is required")
        prefix = settings.AUDIT_CHECKPOINT_PREFIX.strip("/")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]{0,127}", prefix) or ".." in prefix or "//" in prefix:
            raise CommandError("AUDIT_CHECKPOINT_PREFIX is invalid")

        created_at = timezone.now()
        body = canonical_json(checkpoint_document(created_at))
        digest = hashlib.sha256(body).hexdigest()
        key = f"{prefix}/{created_at:%Y/%m/%d}/{created_at:%Y%m%dT%H%M%S%fZ}.json"
        try:
            boto3.client("s3", region_name=settings.S3_REGION).put_object(
                Bucket=settings.AUDIT_CHECKPOINT_BUCKET,
                Key=key,
                Body=body,
                ContentType="application/json",
                Metadata={"sha256": digest},
            )
            boto3.client("cloudwatch", region_name=settings.S3_REGION).put_metric_data(
                Namespace="Trishul/Operations",
                MetricData=[
                    {
                        "MetricName": "AuditCheckpointPublished",
                        "Timestamp": created_at,
                        "Value": 1,
                        "Unit": "Count",
                    }
                ],
            )
        except (BotoCoreError, ClientError) as exc:
            raise CommandError("Audit checkpoint publication failed") from exc
        self.stdout.write(f"s3://{settings.AUDIT_CHECKPOINT_BUCKET}/{key} sha256={digest}")
