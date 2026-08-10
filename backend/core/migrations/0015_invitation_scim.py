import hashlib
import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.db.models.manager
import django.utils.timezone


def secure_existing_invitations(apps, schema_editor):
    Invitation = apps.get_model("core", "TenantInvitation")
    now = django.utils.timezone.now()
    for invitation in Invitation.objects.filter(token_hash__isnull=True).iterator():
        invitation.token_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        if invitation.accepted_at is None:
            invitation.revoked_at = now
        invitation.save(update_fields=["token_hash", "revoked_at"])


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        for table in ("core_scimcredential", "core_scimidentity"):
            cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            cursor.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({tenant}) WITH CHECK ({tenant})")


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table in ("core_scimcredential", "core_scimidentity"):
            cursor.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")


class Migration(migrations.Migration):
    dependencies = [("core", "0014_identity_security")]

    operations = [
        migrations.AddField(
            model_name="tenantinvitation",
            name="revoked_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="tenantinvitation",
            name="token_hash",
            field=models.CharField(editable=False, max_length=64, null=True, unique=True),
        ),
        migrations.RunPython(secure_existing_invitations, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="tenantinvitation",
            name="token_hash",
            field=models.CharField(editable=False, max_length=64, unique=True),
        ),
        migrations.CreateModel(
            name="ScimCredential",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("name", models.CharField(max_length=120)),
                ("token_hash", models.CharField(editable=False, max_length=64, unique=True)),
                ("default_role", models.CharField(choices=[("admin", "Organization administrator"), ("ciso", "Security leader"), ("architect", "Security architect"), ("appsec", "Application security engineer"), ("assessor", "Security assessor"), ("developer", "Developer"), ("manager", "Engineering manager"), ("auditor", "Auditor"), ("executive", "Executive"), ("platform_admin", "Platform administrator"), ("firm_admin", "Audit firm administrator"), ("audit_manager", "Audit manager"), ("reviewer", "Reviewer / QA"), ("org_admin", "Auditee administrator"), ("compliance_manager", "Compliance manager"), ("control_owner", "Control owner"), ("risk_owner", "Risk owner"), ("vendor_manager", "Vendor manager")], max_length=30)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant")),
            ],
            options={"base_manager_name": "all_objects"},
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("all_objects", django.db.models.manager.Manager()),
            ],
        ),
        migrations.CreateModel(
            name="ScimIdentity",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("external_id", models.CharField(blank=True, max_length=200)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
            ],
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("all_objects", django.db.models.manager.Manager()),
            ],
        ),
        migrations.AddConstraint(
            model_name="scimidentity",
            constraint=models.UniqueConstraint(fields=("tenant", "user"), name="scim_identity_tenant_user_uniq"),
        ),
        migrations.AddConstraint(
            model_name="scimidentity",
            constraint=models.UniqueConstraint(condition=models.Q(("external_id__gt", "")), fields=("tenant", "external_id"), name="scim_identity_tenant_external_uniq"),
        ),
        migrations.RunPython(apply_security, remove_security),
    ]
