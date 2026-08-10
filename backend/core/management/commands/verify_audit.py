import hashlib
import json

from django.core.management.base import BaseCommand, CommandError

from core.audit import load_checkpoint
from core.models import AuditEvent, Tenant
from core.tenancy import database_tenant_context


class Command(BaseCommand):
    help = "Verify every tenant audit hash chain."

    def add_arguments(self, parser):
        parser.add_argument("--checkpoint", help="Trusted checkpoint JSON downloaded outside the workload account.")

    def handle(self, **options):
        checkpoint = None
        if options["checkpoint"]:
            try:
                checkpoint = load_checkpoint(options["checkpoint"])
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise CommandError(f"Invalid audit checkpoint: {exc}") from exc
        verified_tenants = set()
        for tenant in Tenant.objects.all().iterator():
            previous_hash = ""
            hashes = set()
            with database_tenant_context(tenant.id):
                for event in AuditEvent.objects.order_by("occurred_at", "id").iterator():
                    payload = json.dumps(
                        {
                            "tenant": str(tenant.id),
                            "actor_type": event.actor_type,
                            "actor_id": event.actor_id,
                            "action": event.action,
                            "resource_type": event.resource_type,
                            "resource_id": event.resource_id,
                            "details": event.details,
                            "occurred_at": event.occurred_at.isoformat(),
                            "previous_hash": previous_hash,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    expected = hashlib.sha256(payload.encode()).hexdigest()
                    if event.previous_hash != previous_hash or event.event_hash != expected:
                        raise CommandError(f"Audit chain failed for tenant {tenant.id} at event {event.id}")
                    previous_hash = event.event_hash
                    hashes.add(previous_hash)
            tenant_id = str(tenant.id)
            verified_tenants.add(tenant_id)
            trusted_hash = checkpoint.get(tenant_id) if checkpoint is not None else None
            if trusted_hash and trusted_hash not in hashes:
                raise CommandError(f"Trusted audit checkpoint is not in the chain for tenant {tenant.id}")
        missing = checkpoint.keys() - verified_tenants if checkpoint is not None else set()
        if missing:
            raise CommandError(f"Trusted audit checkpoint contains unknown tenant {sorted(missing)[0]}")
        self.stdout.write(self.style.SUCCESS("Audit chains verified"))
