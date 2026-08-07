import uuid

import django.db.models.deletion
import django.db.models.manager
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("core", "0006_saas_tenant_security")]
    operations = [
        migrations.CreateModel(
            name="WorkflowTransition",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("machine", models.CharField(max_length=80)),
                ("machine_version", models.PositiveSmallIntegerField()),
                ("entity_type", models.CharField(max_length=100)),
                ("entity_id", models.UUIDField()),
                ("event", models.CharField(max_length=80)),
                ("from_state", models.CharField(blank=True, max_length=40)),
                ("to_state", models.CharField(max_length=40)),
                ("entity_version_before", models.PositiveIntegerField()),
                ("entity_version_after", models.PositiveIntegerField()),
                ("actor_type", models.CharField(max_length=20)),
                ("actor_id", models.CharField(max_length=200)),
                ("engagement_id", models.UUIDField(blank=True, null=True)),
                ("reason", models.TextField(blank=True, max_length=4000)),
                ("reason_code", models.CharField(blank=True, max_length=80)),
                ("idempotency_key", models.CharField(blank=True, max_length=200)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                (
                    "actor_tenant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="workflow_actions",
                        to="core.tenant",
                    ),
                ),
                (
                    "audit_event",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="workflow_transition",
                        to="core.auditevent",
                    ),
                ),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant")),
            ],
            options={"ordering": ["created_at", "id"]},
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("all_objects", django.db.models.manager.Manager()),
            ],
        ),
        migrations.AddIndex(
            model_name="workflowtransition",
            index=models.Index(fields=["tenant", "machine", "entity_id", "created_at"], name="workflow_timeline_idx"),
        ),
        migrations.AddConstraint(
            model_name="workflowtransition",
            constraint=models.UniqueConstraint(
                condition=models.Q(("idempotency_key__gt", "")),
                fields=("tenant", "machine", "entity_id", "idempotency_key"),
                name="workflow_idempotency_uniq",
            ),
        ),
    ]
