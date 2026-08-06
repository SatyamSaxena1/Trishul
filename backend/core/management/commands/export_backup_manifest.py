import json

from django.core.management.base import BaseCommand
from django.utils import timezone

from core.audit import latest_audit_heads
from core.models import Evidence, Report, RepositoryVersion, Tenant
from core.tenancy import database_tenant_context


class Command(BaseCommand):
    help = "Write a non-sensitive object and audit consistency manifest to stdout."

    def handle(self, **options):
        audit_heads = {item["tenant_id"]: item["last_audit_hash"] for item in latest_audit_heads()}
        tenants = []
        for tenant in Tenant.objects.order_by("id").iterator():
            objects = []
            with database_tenant_context(tenant.id):
                for model, kind in ((RepositoryVersion, "repository"), (Evidence, "evidence"), (Report, "report")):
                    for item in model.objects.order_by("id").iterator():
                        objects.append(
                            {
                                "kind": kind,
                                "id": str(item.id),
                                "object_key": item.object_key,
                                "sha256": getattr(item, "sha256", getattr(item, "content_hash", "")),
                            }
                        )
            tenants.append(
                {
                    "tenant_id": str(tenant.id),
                    "objects": objects,
                    "last_audit_hash": audit_heads[str(tenant.id)],
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
