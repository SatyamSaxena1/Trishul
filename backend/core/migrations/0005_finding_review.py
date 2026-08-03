import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0004_job_application"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="FindingReview",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("decision", models.CharField(choices=[("accepted", "Accepted"), ("false_positive", "False positive"), ("duplicate", "Duplicate"), ("needs_context", "Needs context")], max_length=20)),
                ("reason_codes", models.JSONField(blank=True, default=list)),
                ("comment", models.TextField(blank=True, max_length=2000)),
                ("reviewed_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("finding", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="reviews", to="core.finding")),
                ("reviewer", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="finding_reviews", to=settings.AUTH_USER_MODEL)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.tenant")),
            ],
            options={"base_manager_name": "all_objects"},
            managers=[
                ("objects", models.Manager()),
                ("all_objects", models.Manager()),
            ],
        ),
    ]
