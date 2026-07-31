from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0004_job_application")]

    operations = [
        migrations.AddField(
            model_name="job", name="recovery_count", field=models.PositiveSmallIntegerField(default=0)
        ),
        migrations.AddField(
            model_name="job", name="started_at", field=models.DateTimeField(blank=True, null=True)
        ),
        migrations.AddField(
            model_name="job", name="finished_at", field=models.DateTimeField(blank=True, null=True)
        ),
    ]
