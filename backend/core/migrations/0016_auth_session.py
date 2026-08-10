import uuid

from django.conf import settings
from django.core.validators import MinValueValidator
from django.db import migrations, models
import django.db.models.deletion
import django.db.models.manager
import django.utils.timezone


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE core_authsession ENABLE ROW LEVEL SECURITY")
        cursor.execute("ALTER TABLE core_authsession FORCE ROW LEVEL SECURITY")
        cursor.execute(
            f"CREATE POLICY tenant_isolation ON core_authsession USING ({tenant}) WITH CHECK ({tenant})"
        )


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        with schema_editor.connection.cursor() as cursor:
            cursor.execute("DROP POLICY IF EXISTS tenant_isolation ON core_authsession")


class Migration(migrations.Migration):
    dependencies = [("core", "0015_invitation_scim")]

    operations = [
        migrations.AlterField(
            model_name="tenantsessionpolicy",
            name="idle_timeout_minutes",
            field=models.PositiveIntegerField(default=30, validators=[MinValueValidator(1)]),
        ),
        migrations.AlterField(
            model_name="tenantsessionpolicy",
            name="absolute_timeout_minutes",
            field=models.PositiveIntegerField(default=720, validators=[MinValueValidator(1)]),
        ),
        migrations.AlterField(
            model_name="tenantsessionpolicy",
            name="max_concurrent_sessions",
            field=models.PositiveSmallIntegerField(default=5, validators=[MinValueValidator(1)]),
        ),
        migrations.CreateModel(
            name="AuthSession",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("token_hash", models.CharField(editable=False, max_length=64, unique=True)),
                ("started_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("last_seen_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("absolute_expires_at", models.DateTimeField()),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "indexes": [models.Index(fields=["tenant", "user", "revoked_at"], name="auth_session_active_idx")]
            },
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("all_objects", django.db.models.manager.Manager()),
            ],
        ),
        migrations.RunPython(apply_security, remove_security),
    ]
