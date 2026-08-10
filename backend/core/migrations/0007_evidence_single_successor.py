from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0006_saas_tenant_security")]

    operations = [
        migrations.AddConstraint(
            model_name="evidence",
            constraint=models.UniqueConstraint(
                condition=models.Q(("supersedes__isnull", False)),
                fields=("supersedes",),
                name="evidence_single_successor_uniq",
            ),
        )
    ]
