from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0004_job_application")]

    operations = [
        migrations.AddField(model_name="job", name="lease_token", field=models.UUIDField(blank=True, editable=False, null=True)),
        migrations.AddField(model_name="job", name="heartbeat_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="job", name="analyzer_ref", field=models.CharField(blank=True, max_length=200)),
        migrations.AddField(model_name="job", name="scratch_ref", field=models.CharField(blank=True, max_length=200)),
    ]
