"""Install the shipped policy pack and default profiles for a tenant.

Run once per tenant after ``bootstrap_tenant``, and again after any release that
publishes a new pack version. Idempotent: re-running an unchanged release is a
no-op, and re-running against a *modified* pack at the same version fails loudly
rather than rewriting a pack that historical decisions already reference.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from core.models import AuditEvent, Tenant
from core.tenancy import tenant_context

from ...models import DecisionThresholdProfile, PolicyProfile
from ...policy import REGISTRY
from ...policy.registry import PolicyPackConflict, sync_pack


class Command(BaseCommand):
    help = "Install the Deployment Assurance policy pack and default profiles for a tenant."

    def add_arguments(self, parser):
        parser.add_argument("tenant_slug", help="Slug of an existing tenant.")
        parser.add_argument(
            "--threshold-name",
            default="production-default",
            help="Name for the default decision threshold profile.",
        )

    def handle(self, *args, **options):
        slug = options["tenant_slug"]
        try:
            tenant = Tenant.objects.get(slug=slug)
        except Tenant.DoesNotExist as exc:
            raise CommandError(f"No tenant with slug {slug!r}.") from exc

        with transaction.atomic(), tenant_context(tenant.id):
            try:
                pack = sync_pack(tenant)
            except PolicyPackConflict as exc:
                raise CommandError(str(exc)) from exc

            thresholds, thresholds_created = DecisionThresholdProfile.all_objects.get_or_create(
                tenant=tenant,
                name=options["threshold_name"],
                profile_version="1.0.0",
                defaults={"is_default": True},
            )
            profile, profile_created = PolicyProfile.all_objects.get_or_create(
                tenant=tenant,
                name=f"{pack.key}-default",
                defaults={"policy_pack": pack, "threshold_profile": thresholds, "is_default": True},
            )
            AuditEvent.append(
                tenant=tenant,
                actor_type="system",
                actor_id="bootstrap_assurance",
                action="deployment_policy.installed",
                resource_type="deployment_assurance.policypack",
                resource_id=pack.id,
                details={
                    "pack": f"{pack.key}@{pack.pack_version}",
                    "content_hash": pack.content_hash,
                    "rules": len(REGISTRY),
                },
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Pack {pack.key}@{pack.pack_version} ({len(REGISTRY)} rules, hash {pack.content_hash[:12]}…) "
                f"is installed for tenant {slug}."
            )
        )
        self.stdout.write(
            f"  threshold profile: {thresholds.name}@{thresholds.profile_version} "
            f"({'created' if thresholds_created else 'existing'})"
        )
        self.stdout.write(f"  policy profile:    {profile.name} ({'created' if profile_created else 'existing'})")
