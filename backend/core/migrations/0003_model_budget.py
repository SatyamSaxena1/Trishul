from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0002_tenant_security")]
    operations = [
        migrations.AddField(
            model_name="modelconfiguration",
            name="requests_per_minute",
            field=models.PositiveSmallIntegerField(default=30),
        ),
        migrations.AddField(
            model_name="modelconfiguration",
            name="daily_token_limit",
            field=models.PositiveIntegerField(default=1_000_000),
        ),
    ]

