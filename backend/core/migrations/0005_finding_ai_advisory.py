from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0004_job_application")]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="ai_advisory",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
