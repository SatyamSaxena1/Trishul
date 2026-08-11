from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0023_fix_delegated_onboarding_policies")]
    operations = [
        migrations.AlterField(
            model_name="auditevent",
            name="details",
            field=models.JSONField(blank=True, default=dict),
        )
    ]
