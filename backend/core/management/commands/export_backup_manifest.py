import json

from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import AuditEvent, Evidence, Report, RepositoryVersion, Tenant


class Command(BaseCommand):
    help = "Write a non-sensitive object and audit consistency manifest to stdout."

    def handle(self, **options):
        tenants = []
        for tenant in Tenant.objects.order_by("id").iterator():
            objects = []
            for model, kind in ((RepositoryVersion, "repository"), (Evidence, "evidence"), (Report, "report")):
                for item in model.all_objects.filter(tenant=tenant).order_by("id").iterator():
                    objects.append(
                        {
                            "kind": kind,
                            "id": str(item.id),
                            "object_key": item.object_key,
                            "sha256": getattr(item, "sha256", getattr(item, "content_hash", "")),
                        }
                    )
            last_audit = AuditEvent.all_objects.filter(tenant=tenant).order_by("-occurred_at", "-id").first()
            tenants.append(
                {
                    "tenant_id": str(tenant.id),
                    "objects": objects,
                    "last_audit_hash": last_audit.event_hash if last_audit else "",
                }
            )
        self.stdout.write(
            json.dumps(
                {
                    "format": "ai-trishul-backup-manifest-v1",
                    "created_at": timezone.now().isoformat(),
                    "tenants": tenants,
                },
                sort_keys=True,
            )
        )
