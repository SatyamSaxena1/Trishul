"""Force tenant isolation on identity configuration."""

from django.db import migrations

TABLES = ("core_identityproviderconfiguration", "core_tenantsessionpolicy")


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        for table in TABLES:
            cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            cursor.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({tenant}) WITH CHECK ({tenant})")


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table in TABLES:
            cursor.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")


class Migration(migrations.Migration):
    dependencies = [("core", "0013_identityproviderconfiguration_tenantsessionpolicy")]
    operations = [migrations.RunPython(apply_security, remove_security)]
