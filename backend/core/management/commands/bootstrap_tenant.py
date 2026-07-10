from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from core.models import Membership, Tenant
from core.tenancy import tenant_context


class Command(BaseCommand):
    help = "Create or update the first OIDC user and tenant administrator membership."

    def add_arguments(self, parser):
        parser.add_argument("--subject", required=True)
        parser.add_argument("--email", required=True)
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--tenant-name", required=True)

    @transaction.atomic
    def handle(self, **options):
        if len(options["subject"]) > 150:
            raise CommandError("OIDC subject exceeds Django's 150-character username limit")
        tenant, _ = Tenant.objects.update_or_create(
            slug=options["tenant_slug"], defaults={"name": options["tenant_name"], "is_active": True}
        )
        user, _ = get_user_model().objects.update_or_create(
            username=options["subject"], defaults={"email": options["email"], "is_active": True}
        )
        with tenant_context(tenant.id):
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant.id)])
            Membership.all_objects.update_or_create(
                tenant=tenant, user=user, defaults={"role": Membership.Role.ADMIN, "is_active": True}
            )
        self.stdout.write(self.style.SUCCESS(f"Bootstrapped tenant {tenant.slug} for subject {user.username}"))
