from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from core.dev_auth import PERSONAS
from core.models import (
    Application,
    ControlAssignment,
    Engagement,
    EngagementMember,
    Membership,
    OrganisationControl,
    Organization,
    Tenant,
    TenantRelationship,
    UnifiedControlObjective,
    Workspace,
)
from core.tenancy import tenant_context


class Command(BaseCommand):
    help = "Seed deterministic local tenants, personas, and workflow demo data."

    @transaction.atomic
    def handle(self, **options):
        if not settings.DEBUG or not settings.TRISHUL_DEV_AUTH:
            raise CommandError("seed_dev requires DEBUG=true and TRISHUL_DEV_AUTH=true")

        tenants = {
            "dev-platform": Tenant.objects.update_or_create(
                slug="dev-platform",
                defaults={"name": "Trishul Platform", "tenant_type": Tenant.Type.PLATFORM, "is_active": True},
            )[0],
            "dev-firm": Tenant.objects.update_or_create(
                slug="dev-firm",
                defaults={"name": "Trishul Audit Firm", "tenant_type": Tenant.Type.AUDIT_FIRM, "is_active": True},
            )[0],
            "dev-auditee": Tenant.objects.update_or_create(
                slug="dev-auditee",
                defaults={
                    "name": "Acme Demo Organisation",
                    "tenant_type": Tenant.Type.AUDITEE,
                    "auditee_mode": Tenant.AuditeeMode.FIRM_MANAGED,
                    "is_active": True,
                },
            )[0],
        }
        users = {}
        for username, _, role, tenant_slug in PERSONAS:
            user, _ = get_user_model().objects.update_or_create(
                username=username,
                defaults={"email": f"{username}@example.test", "is_active": True},
            )
            user.set_unusable_password()
            user.save(update_fields=["password"])
            users[username] = user
            tenant = tenants[tenant_slug]
            with tenant_context(tenant.id):
                Membership.all_objects.update_or_create(
                    tenant=tenant, user=user, defaults={"role": role, "is_active": True}
                )

        firm, auditee = tenants["dev-firm"], tenants["dev-auditee"]
        with tenant_context(firm.id):
            TenantRelationship.all_objects.update_or_create(
                tenant=firm,
                related_tenant=auditee,
                relationship=TenantRelationship.Relationship.MANAGES,
                defaults={"status": "active"},
            )
        with tenant_context(auditee.id):
            organization, _ = Organization.all_objects.get_or_create(tenant=auditee, name="Acme Demo")
            workspace, _ = Workspace.all_objects.get_or_create(
                tenant=auditee, organization=organization, name="Production"
            )
            application, _ = Application.all_objects.get_or_create(
                tenant=auditee,
                workspace=workspace,
                name="Payments API",
                defaults={"description": "Seeded application for local workflow testing.", "criticality": 5},
            )
            objective, _ = UnifiedControlObjective.all_objects.get_or_create(
                tenant=auditee,
                code="UCO-DEV-IAM-001",
                defaults={
                    "domain": "identity",
                    "objective": "Require strong authentication for privileged access.",
                    "control_type": UnifiedControlObjective.ControlType.PREVENTIVE,
                    "nature": UnifiedControlObjective.Nature.TECHNICAL,
                },
            )
            control, _ = OrganisationControl.all_objects.get_or_create(
                tenant=auditee,
                application=application,
                unified_control=objective,
                defaults={"owner": users["dev-control-owner"]},
            )
            ControlAssignment.all_objects.get_or_create(
                tenant=auditee, organisation_control=control, assignee=users["dev-control-owner"]
            )

        today = timezone.localdate()
        with tenant_context(firm.id):
            engagement, _ = Engagement.all_objects.get_or_create(
                tenant=firm,
                reference="DEV-ENG-001",
                defaults={
                    "auditee_tenant": auditee,
                    "name": "Acme annual audit",
                    "status": Engagement.Status.ACTIVE,
                    "starts_on": today - timedelta(days=30),
                    "ends_on": today + timedelta(days=335),
                    "framework_scope": ["DEV"],
                    "application_scope": [str(application.id)],
                    "control_scope": [objective.code],
                    "created_by": users["dev-audit-manager"],
                    "approved_by": users["dev-firm-admin"],
                },
            )
            for username, role in (
                ("dev-audit-manager", EngagementMember.Role.LEAD),
                ("dev-auditor", EngagementMember.Role.AUDITOR),
            ):
                EngagementMember.all_objects.update_or_create(
                    tenant=firm,
                    engagement=engagement,
                    user=users[username],
                    defaults={"role": role, "is_active": True},
                )

        self.stdout.write(self.style.SUCCESS("Seeded local development personas and demo workflow data."))
