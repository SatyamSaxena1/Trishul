"""Database-enforced tenant isolation and append-only reuse decisions."""

from django.db import migrations


RELATIONSHIPS = (
    ("core_evidencereuseevaluation", "evidence_id", "core_evidence"),
    ("core_evidencereuseevaluation", "organisation_control_id", "core_organisationcontrol"),
    ("core_evidencereuseevaluation", "requirement_id", "core_requirement"),
    ("core_evidencereuseevaluation", "unified_control_id", "core_unifiedcontrolobjective"),
    ("core_evidencereuseevaluation", "mapping_id", "core_frameworkcontrolmapping"),
    ("core_compliancegap", "evidence_id", "core_evidence"),
    ("core_compliancegap", "requirement_id", "core_requirement"),
)


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    table = quote("core_evidencereuseevaluation")
    tenant = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE core_frameworkcontrolmapping ADD CONSTRAINT "
            "core_frameworkcontrolmapping_id_tenant_uniq UNIQUE (id, tenant_id)"
        )
        cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        cursor.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({tenant}) WITH CHECK ({tenant})")
        for child, column, parent in RELATIONSHIPS:
            name = f"same_tenant_{child.removeprefix('core_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(
                f"ALTER TABLE {quote(child)} ADD CONSTRAINT {quote(name)} "
                f"FOREIGN KEY ({quote(column)}, tenant_id) REFERENCES {quote(parent)} (id, tenant_id) "
                "DEFERRABLE INITIALLY DEFERRED"
            )
        cursor.execute(
            f"CREATE TRIGGER core_evidencereuseevaluation_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION trishul_reject_audit_mutation()"
        )


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS core_evidencereuseevaluation_immutable ON core_evidencereuseevaluation")
        for child, column, _ in reversed(RELATIONSHIPS):
            name = f"same_tenant_{child.removeprefix('core_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(f"ALTER TABLE {quote(child)} DROP CONSTRAINT IF EXISTS {quote(name)}")
        cursor.execute("DROP POLICY IF EXISTS tenant_isolation ON core_evidencereuseevaluation")
        cursor.execute(
            "ALTER TABLE core_frameworkcontrolmapping DROP CONSTRAINT IF EXISTS "
            "core_frameworkcontrolmapping_id_tenant_uniq"
        )


class Migration(migrations.Migration):
    dependencies = [("core", "0009_assessment_audit_period_end_and_more")]
    operations = [migrations.RunPython(apply_security, remove_security)]
