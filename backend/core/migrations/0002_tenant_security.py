import os
import re

from django.db import migrations


RELATIONSHIPS = [
    ("core_workspace", "organization_id", "core_organization"),
    ("core_application", "workspace_id", "core_workspace"),
    ("core_repository", "application_id", "core_application"),
    ("core_repositoryversion", "repository_id", "core_repository"),
    ("core_scan", "repository_version_id", "core_repositoryversion"),
    ("core_finding", "scan_id", "core_scan"),
    ("core_findingevidence", "finding_id", "core_finding"),
    ("core_threatmodel", "application_id", "core_application"),
    ("core_architecturecomponent", "threat_model_id", "core_threatmodel"),
    ("core_dataflow", "threat_model_id", "core_threatmodel"),
    ("core_dataflow", "source_id", "core_architecturecomponent"),
    ("core_dataflow", "destination_id", "core_architecturecomponent"),
    ("core_threat", "threat_model_id", "core_threatmodel"),
    ("core_threat", "component_id", "core_architecturecomponent"),
    ("core_requirement", "framework_version_id", "core_frameworkversion"),
    ("core_assessment", "application_id", "core_application"),
    ("core_assessment", "framework_version_id", "core_frameworkversion"),
    ("core_evidence", "assessment_id", "core_assessment"),
    ("core_assessmentresponse", "assessment_id", "core_assessment"),
    ("core_assessmentresponse", "requirement_id", "core_requirement"),
    ("core_assessmentevidence", "response_id", "core_assessmentresponse"),
    ("core_assessmentevidence", "evidence_id", "core_evidence"),
    ("core_compliancegap", "response_id", "core_assessmentresponse"),
    ("core_risk", "application_id", "core_application"),
    ("core_risklink", "risk_id", "core_risk"),
    ("core_riskscore", "risk_id", "core_risk"),
    ("core_remediation", "risk_id", "core_risk"),
    ("core_riskacceptance", "risk_id", "core_risk"),
    ("core_approval", "acceptance_id", "core_riskacceptance"),
    ("core_aianalysisrun", "model_configuration_id", "core_modelconfiguration"),
    ("core_aianalysisrun", "prompt_version_id", "core_promptversion"),
    ("core_report", "application_id", "core_application"),
]


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    tenant_expression = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    tenant_tables = []
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE core_tenant ENABLE ROW LEVEL SECURITY")
        cursor.execute("ALTER TABLE core_tenant FORCE ROW LEVEL SECURITY")
        cursor.execute(
            """
            CREATE POLICY tenant_visible ON core_tenant FOR SELECT USING (
                id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid
                OR EXISTS (
                    SELECT 1 FROM core_membership m
                    WHERE m.tenant_id = core_tenant.id
                    AND m.user_id = NULLIF(current_setting('trishul.user_id', true), '')::integer
                    AND m.is_active
                )
                OR EXISTS (
                    SELECT 1 FROM core_serviceaccount s
                    WHERE s.tenant_id = core_tenant.id
                    AND s.id = NULLIF(current_setting('trishul.service_account_id', true), '')::uuid
                )
            )
            """
        )
        for model in apps.get_app_config("core").get_models():
            if "tenant" not in {field.name for field in model._meta.fields}:
                continue
            table = quote(model._meta.db_table)
            tenant_tables.append(model._meta.db_table)
            cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            if model._meta.model_name == "membership":
                cursor.execute(
                    f"CREATE POLICY tenant_select ON {table} FOR SELECT USING "
                    f"({tenant_expression} OR user_id = NULLIF(current_setting('trishul.user_id', true), '')::integer)"
                )
                cursor.execute(f"CREATE POLICY tenant_modify ON {table} FOR ALL USING ({tenant_expression}) WITH CHECK ({tenant_expression})")
            elif model._meta.model_name == "serviceaccount":
                cursor.execute(
                    f"CREATE POLICY tenant_select ON {table} FOR SELECT USING "
                    f"({tenant_expression} OR id = NULLIF(current_setting('trishul.service_account_id', true), '')::uuid)"
                )
                cursor.execute(f"CREATE POLICY tenant_modify ON {table} FOR ALL USING ({tenant_expression}) WITH CHECK ({tenant_expression})")
            else:
                cursor.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({tenant_expression}) WITH CHECK ({tenant_expression})")

        for parent in {parent for _, _, parent in RELATIONSHIPS}:
            constraint = f"{parent}_id_tenant_uniq"[:63]
            cursor.execute(f"ALTER TABLE {quote(parent)} ADD CONSTRAINT {quote(constraint)} UNIQUE (id, tenant_id)")
        for child, column, parent in RELATIONSHIPS:
            constraint = f"same_tenant_{child.removeprefix('core_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(
                f"ALTER TABLE {quote(child)} ADD CONSTRAINT {quote(constraint)} "
                f"FOREIGN KEY ({quote(column)}, tenant_id) REFERENCES {quote(parent)} (id, tenant_id) DEFERRABLE INITIALLY DEFERRED"
            )

        cursor.execute(
            "CREATE FUNCTION trishul_reject_audit_mutation() RETURNS trigger AS $$ "
            "BEGIN RAISE EXCEPTION 'audit events are immutable'; END; $$ LANGUAGE plpgsql"
        )
        cursor.execute(
            "CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON core_auditevent "
            "FOR EACH ROW EXECUTE FUNCTION trishul_reject_audit_mutation()"
        )
        app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
            raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        if cursor.fetchone():
            role = quote(app_role)
            cursor.execute(f"CREATE POLICY app_tenant_list ON core_tenant FOR SELECT TO {role} USING (true)")
            cursor.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
            cursor.execute(f"GRANT SELECT ON core_tenant TO {role}")
            for table_name in tenant_tables:
                privileges = "SELECT, INSERT" if table_name == "core_auditevent" else "SELECT, INSERT, UPDATE, DELETE"
                cursor.execute(f"GRANT {privileges} ON {quote(table_name)} TO {role}")
            cursor.execute(f"GRANT SELECT, INSERT, UPDATE ON auth_user TO {role}")
            cursor.execute(f"GRANT USAGE, SELECT ON SEQUENCE auth_user_id_seq TO {role}")
            for table_name in ("django_migrations", "django_content_type", "auth_permission"):
                cursor.execute(f"GRANT SELECT ON {quote(table_name)} TO {role}")


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        with schema_editor.connection.cursor() as cursor:
            cursor.execute("DROP FUNCTION IF EXISTS trishul_reject_audit_mutation() CASCADE")


class Migration(migrations.Migration):
    dependencies = [("core", "0001_initial")]
    operations = [migrations.RunPython(apply_security, remove_security)]
