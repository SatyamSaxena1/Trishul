import hashlib
import json

from django.core.management.base import BaseCommand, CommandError

from core.models import AuditEvent, Tenant


class Command(BaseCommand):
    help = "Verify every tenant audit hash chain."

    def handle(self, **options):
        for tenant in Tenant.objects.all().iterator():
            previous_hash = ""
            events = AuditEvent.all_objects.filter(tenant=tenant).order_by("occurred_at", "id")
            for event in events.iterator():
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
        self.stdout.write(self.style.SUCCESS("Audit chains verified"))
