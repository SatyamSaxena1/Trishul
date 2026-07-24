import os
import re
import uuid

import django.db.models.deletion
from django.db import migrations, models


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
        raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
    tenant_expression = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        role_exists = bool(cursor.fetchone())
        for table in ("core_stagingtarget", "core_webhookdelivery"):
            name = quote(table)
            cursor.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
            cursor.execute(
                f"CREATE POLICY tenant_isolation ON {name} USING ({tenant_expression}) WITH CHECK ({tenant_expression})"
            )
            if role_exists:
                cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO {quote(app_role)}")
        cursor.execute(
            "ALTER TABLE core_stagingtarget ADD CONSTRAINT same_tenant_stagingtarget_application "
            "FOREIGN KEY (application_id, tenant_id) REFERENCES core_application (id, tenant_id) "
            "DEFERRABLE INITIALLY DEFERRED"
        )
        cursor.execute(
            "ALTER TABLE core_webhookdelivery ADD CONSTRAINT same_tenant_webhookdelivery_repository "
            "FOREIGN KEY (repository_id, tenant_id) REFERENCES core_repository (id, tenant_id) "
            "DEFERRABLE INITIALLY DEFERRED"
        )


class Migration(migrations.Migration):
    dependencies = [("core", "0004_job_application")]
    operations = [
        migrations.AddField(
            model_name="repository",
            name="ci_secret_ciphertext",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="repository",
            name="clone_url",
            field=models.URLField(blank=True, max_length=600),
        ),
        migrations.AddField(
            model_name="repository",
            name="credential_ciphertext",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="repository",
            name="status_credential_ciphertext",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="repository",
            name="default_branch",
            field=models.CharField(default="main", max_length=200),
        ),
        migrations.AddField(
            model_name="repository",
            name="external_id",
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name="repository",
            name="installation_id",
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name="repository",
            name="webhook_secret_ciphertext",
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name="repository",
            name="source_type",
            field=models.CharField(
                choices=[("upload", "Upload"), ("github", "GitHub"), ("gitlab", "GitLab")],
                default="upload",
                max_length=30,
            ),
        ),
        migrations.RemoveConstraint(model_name="repositoryversion", name="repository_version_hash_uniq"),
        migrations.AddField(
            model_name="repositoryversion",
            name="commit_sha",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="repositoryversion",
            name="ref",
            field=models.CharField(blank=True, max_length=300),
        ),
        migrations.AddField(
            model_name="repositoryversion",
            name="source_event",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddConstraint(
            model_name="repositoryversion",
            constraint=models.UniqueConstraint(
                fields=("tenant", "repository", "sha256", "commit_sha"),
                name="repository_version_source_uniq",
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="result_object_key",
            field=models.CharField(blank=True, max_length=600),
        ),
        migrations.AddField(
            model_name="findingevidence",
            name="evidence_type",
            field=models.CharField(
                choices=[
                    ("source", "Source"),
                    ("dependency", "Dependency"),
                    ("http", "HTTP"),
                    ("configuration", "Configuration"),
                    ("test", "Test"),
                ],
                default="source",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="findingevidence",
            name="location",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AlterField(
            model_name="findingevidence",
            name="file_path",
            field=models.CharField(blank=True, max_length=600),
        ),
        migrations.AlterField(
            model_name="findingevidence",
            name="start_line",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="findingevidence",
            name="end_line",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="findingevidence",
            name="snippet_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.CreateModel(
            name="StagingTarget",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("url", models.URLField(max_length=600)),
                ("approved", models.BooleanField(default=False)),
                (
                    "application",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="staging_targets",
                        to="core.application",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant"),
                ),
            ],
            options={},
            managers=[
                ("objects", models.Manager()),
                ("all_objects", models.Manager()),
            ],
        ),
        migrations.AddConstraint(
            model_name="stagingtarget",
            constraint=models.UniqueConstraint(
                fields=("tenant", "application", "url"), name="staging_target_url_uniq"
            ),
        ),
        migrations.CreateModel(
            name="WebhookDelivery",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("provider", models.CharField(max_length=20)),
                ("delivery_id", models.CharField(max_length=200)),
                ("commit_sha", models.CharField(max_length=64)),
                ("ref", models.CharField(blank=True, max_length=300)),
                ("event", models.CharField(max_length=80)),
                (
                    "repository",
                    models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.repository"),
                ),
                (
                    "tenant",
                    models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant"),
                ),
            ],
            options={},
            managers=[
                ("objects", models.Manager()),
                ("all_objects", models.Manager()),
            ],
        ),
        migrations.AddConstraint(
            model_name="webhookdelivery",
            constraint=models.UniqueConstraint(
                fields=("tenant", "repository", "provider", "delivery_id"),
                name="webhook_delivery_repository_uniq",
            ),
        ),
        migrations.RunPython(apply_security, migrations.RunPython.noop),
    ]
