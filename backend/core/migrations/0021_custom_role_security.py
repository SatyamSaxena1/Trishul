import os
import re

from django.db import migrations


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    q = schema_editor.connection.ops.quote_name
    tenant = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE core_customrole ENABLE ROW LEVEL SECURITY")
        cursor.execute("ALTER TABLE core_customrole FORCE ROW LEVEL SECURITY")
        cursor.execute(
            f"CREATE POLICY tenant_isolation ON core_customrole USING ({tenant}) WITH CHECK ({tenant})"
        )
        cursor.execute(
            f"ALTER TABLE core_customrole ADD CONSTRAINT {q('custom_role_id_tenant_uniq')} UNIQUE (id, tenant_id)"
        )
        cursor.execute(
            f"ALTER TABLE core_membership ADD CONSTRAINT {q('same_tenant_membership_custom_role')} "
            "FOREIGN KEY (custom_role_id, tenant_id) REFERENCES core_customrole (id, tenant_id) "
            "DEFERRABLE INITIALLY DEFERRED"
        )
        app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
            raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        if cursor.fetchone():
            cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON core_customrole TO {q(app_role)}")


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE core_membership DROP CONSTRAINT IF EXISTS same_tenant_membership_custom_role")
        cursor.execute("DROP POLICY IF EXISTS tenant_isolation ON core_customrole")


class Migration(migrations.Migration):
    dependencies = [("core", "0020_custom_role_personas")]
    operations = [migrations.RunPython(apply_security, remove_security)]
