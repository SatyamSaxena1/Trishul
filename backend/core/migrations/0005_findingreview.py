import uuid

import django.db.models.deletion
import django.db.models.manager
from django.db import migrations, models


def secure_finding_reviews(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE core_findingreview ENABLE ROW LEVEL SECURITY")
        cursor.execute("ALTER TABLE core_findingreview FORCE ROW LEVEL SECURITY")
        cursor.execute(
            "CREATE POLICY tenant_isolation ON core_findingreview "
            "USING (tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid)"
        )
        cursor.execute(
            "ALTER TABLE core_findingreview ADD CONSTRAINT same_tenant_findingreview_finding "
            "FOREIGN KEY (finding_id, tenant_id) REFERENCES core_finding (id, tenant_id) "
            "DEFERRABLE INITIALLY DEFERRED"
        )


class Migration(migrations.Migration):
    dependencies = [("core", "0004_job_application")]

    operations = [
        migrations.CreateModel(
            name="FindingReview",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                (
                    "outcome",
                    models.CharField(
                        choices=[
                            ("accepted", "Accepted"),
                            ("false_positive", "False positive"),
                            ("duplicate", "Duplicate"),
                            ("needs_context", "Needs context"),
                        ],
                        max_length=30,
                    ),
                ),
                ("useful", models.BooleanField(blank=True, null=True)),
                ("feedback", models.TextField(blank=True, max_length=4000)),
                ("unresolved_blocker", models.BooleanField(default=False)),
                (
                    "finding",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, related_name="reviews", to="core.finding"
                    ),
                ),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant")),
            ],
            options={"base_manager_name": "all_objects"},
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("all_objects", django.db.models.manager.Manager()),
            ],
        ),
        migrations.RunPython(secure_finding_reviews, migrations.RunPython.noop),
    ]
