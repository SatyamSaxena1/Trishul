import json
from datetime import datetime, timezone

from django.core.management.base import BaseCommand, CommandError

from core.models import Tenant
from core.reporting import generate_tenant_report


class Command(BaseCommand):
    help = "Generate a tenant-scoped, aggregate operational report as JSON."

    def add_arguments(self, parser):
        parser.add_argument("--tenant", required=True, help="Exact tenant UUID (slugs are intentionally unsupported).")
        parser.add_argument("--since", required=True, help="Inclusive ISO-8601 timestamp with timezone.")
        parser.add_argument("--until", required=True, help="Exclusive ISO-8601 timestamp with timezone.")

    def handle(self, **options):
        try:
            tenant = Tenant.objects.get(pk=options["tenant"])
            since = datetime.fromisoformat(options["since"].replace("Z", "+00:00"))
            until = datetime.fromisoformat(options["until"].replace("Z", "+00:00"))
        except (Tenant.DoesNotExist, ValueError) as exc:
            raise CommandError("Invalid tenant UUID or timestamp.") from exc
        if since.tzinfo is None or until.tzinfo is None or since >= until:
            raise CommandError("Timestamps must include timezone and since must precede until.")
        report = generate_tenant_report(
            tenant=tenant,
            since=since.astimezone(timezone.utc),
            until=until.astimezone(timezone.utc),
        )
        self.stdout.write(json.dumps(report, sort_keys=True, indent=2))
