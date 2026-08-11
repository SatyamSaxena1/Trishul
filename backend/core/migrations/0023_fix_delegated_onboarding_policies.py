import os
import re

from django.db import migrations


TABLES = ("core_tenantsubscription", "core_tenantentitlement", "core_organization", "core_workspace")


def replace_policies(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
        raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
    q = schema_editor.connection.ops.quote_name
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        if not cursor.fetchone():
            return
        role = q(app_role)
        for table in TABLES:
            cursor.execute(f"DROP POLICY IF EXISTS delegated_onboarding ON {table}")
            cursor.execute(
                f"CREATE POLICY delegated_onboarding ON {table} FOR INSERT TO {role} WITH CHECK ("
                "EXISTS (SELECT 1 FROM core_membership m "
                f"JOIN core_tenant target ON target.id = {table}.tenant_id WHERE "
                "m.tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid "
                "AND m.user_id = NULLIF(current_setting('trishul.user_id', true), '')::integer AND m.is_active "
                "AND ((m.role = 'platform_admin' AND target.tenant_type = 'audit_firm') "
                "OR (m.role IN ('firm_admin', 'audit_manager') AND target.tenant_type = 'auditee'))))"
            )


class Migration(migrations.Migration):
    dependencies = [("core", "0022_crosstenantaccessevent_application_id_and_more")]
    operations = [migrations.RunPython(replace_policies, migrations.RunPython.noop)]
