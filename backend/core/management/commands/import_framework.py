import hashlib
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone

from core.models import FrameworkVersion, Requirement, Tenant
from core.tenancy import tenant_context


class Command(BaseCommand):
    help = "Import and approve a versioned framework catalog from reviewed JSON."

    def add_arguments(self, parser):
        parser.add_argument("--tenant", required=True, help="Tenant slug")
        parser.add_argument("--file", required=True)
        parser.add_argument("--source-url", required=True)
        parser.add_argument("--approve", action="store_true")

    @transaction.atomic
    def handle(self, **options):
        path = Path(options["file"])
        raw = path.read_bytes()
        try:
            catalog = json.loads(raw)
            framework = str(catalog["framework"])
            version_name = str(catalog["version"])
            requirements = catalog["requirements"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise CommandError("Catalog must contain framework, version, and requirements") from exc
        if not isinstance(requirements, list) or not requirements:
            raise CommandError("Catalog requirements must be a non-empty list")
        identifiers = [str(item.get("control_id", "")) for item in requirements]
        if any(not identifier for identifier in identifiers) or len(set(identifiers)) != len(identifiers):
            raise CommandError("Every control_id must be non-empty and unique")
        tenant = Tenant.objects.get(slug=options["tenant"])
        catalog_hash = hashlib.sha256(raw).hexdigest()
        with tenant_context(tenant.id):
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant.id)])
            existing = FrameworkVersion.objects.filter(framework=framework, version_name=version_name).first()
            if existing and existing.catalog_hash != catalog_hash:
                raise CommandError("An immutable catalog with this framework version already exists")
            catalog_version = existing or FrameworkVersion.objects.create(
                tenant=tenant,
                framework=framework,
                version_name=version_name,
                source_url=options["source_url"],
                catalog_hash=catalog_hash,
                approved_at=timezone.now() if options["approve"] else None,
            )
            if not existing:
                for item in requirements:
                    Requirement.objects.create(
                        tenant=tenant,
                        framework_version=catalog_version,
                        control_id=str(item["control_id"]),
                        title=str(item.get("title", item["control_id"]))[:300],
                        requirement=str(item["requirement"]),
                    )
        self.stdout.write(
            self.style.SUCCESS(
                f"Imported {framework} {version_name} ({len(requirements)} requirements, sha256:{catalog_hash})"
            )
        )
