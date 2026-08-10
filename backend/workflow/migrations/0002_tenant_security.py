import os
import re

from django.db import migrations


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
        raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
    quote = schema_editor.connection.ops.quote_name
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE workflow_workflowtransition ENABLE ROW LEVEL SECURITY")
        cursor.execute("ALTER TABLE workflow_workflowtransition FORCE ROW LEVEL SECURITY")
        cursor.execute(
            "CREATE POLICY tenant_isolation ON workflow_workflowtransition "
            "USING (tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid)"
        )
        cursor.execute(
            "CREATE TRIGGER workflow_transition_immutable BEFORE UPDATE OR DELETE ON workflow_workflowtransition "
            "FOR EACH ROW EXECUTE FUNCTION trishul_reject_audit_mutation()"
        )
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        if cursor.fetchone():
            cursor.execute(f"GRANT SELECT, INSERT ON workflow_workflowtransition TO {quote(app_role)}")


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS workflow_transition_immutable ON workflow_workflowtransition")
        cursor.execute("DROP POLICY IF EXISTS tenant_isolation ON workflow_workflowtransition")


class Migration(migrations.Migration):
    dependencies = [("workflow", "0001_initial")]
    operations = [migrations.RunPython(apply_security, remove_security)]
