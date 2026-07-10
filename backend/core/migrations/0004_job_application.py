from django.db import migrations, models
import django.db.models.deletion


def add_tenant_constraint(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        with schema_editor.connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE core_job ADD CONSTRAINT same_tenant_job_application "
                "FOREIGN KEY (application_id, tenant_id) REFERENCES core_application (id, tenant_id) "
                "DEFERRABLE INITIALLY DEFERRED"
            )


class Migration(migrations.Migration):
    dependencies = [("core", "0003_model_budget")]
    operations = [
        migrations.AddField(
            model_name="job",
            name="application",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="core.application",
            ),
        ),
        migrations.RunPython(add_tenant_constraint, migrations.RunPython.noop),
    ]

