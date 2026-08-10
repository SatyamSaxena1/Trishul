"""Database isolation and immutability for quality overrides and closure changes."""

from django.db import migrations

TABLES = ("core_evidencequalityoverride", "core_postclosureevidencechange")
RELATIONSHIPS = (
    ("core_evidencequalityoverride", "evidence_id", "core_evidence"),
    ("core_postclosureevidencechange", "organisation_control_id", "core_organisationcontrol"),
    ("core_postclosureevidencechange", "evidence_id", "core_evidence"),
    ("core_postclosureevidencechange", "prior_verdict_id", "core_auditorverdict"),
    ("core_postclosureevidencechange", "evaluation_id", "core_evidencereuseevaluation"),
)


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    tenant = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE core_evidencereuseevaluation ADD CONSTRAINT "
            "core_evidencereuseevaluation_id_tenant_uniq UNIQUE (id, tenant_id)"
        )
        for name in TABLES:
            table = quote(name)
            cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            cursor.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({tenant}) WITH CHECK ({tenant})")
            cursor.execute(
                f"CREATE TRIGGER {quote(name + '_immutable')} BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION trishul_reject_audit_mutation()"
            )
        for child, column, parent in RELATIONSHIPS:
            constraint = f"same_tenant_{child.removeprefix('core_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(
                f"ALTER TABLE {quote(child)} ADD CONSTRAINT {quote(constraint)} "
                f"FOREIGN KEY ({quote(column)}, tenant_id) REFERENCES {quote(parent)} (id, tenant_id) "
                "DEFERRABLE INITIALLY DEFERRED"
            )


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    with schema_editor.connection.cursor() as cursor:
        for child, column, _ in reversed(RELATIONSHIPS):
            constraint = f"same_tenant_{child.removeprefix('core_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(f"ALTER TABLE {quote(child)} DROP CONSTRAINT IF EXISTS {quote(constraint)}")
        for name in TABLES:
            cursor.execute(f"DROP TRIGGER IF EXISTS {quote(name + '_immutable')} ON {quote(name)}")
            cursor.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {quote(name)}")
        cursor.execute(
            "ALTER TABLE core_evidencereuseevaluation DROP CONSTRAINT IF EXISTS "
            "core_evidencereuseevaluation_id_tenant_uniq"
        )


class Migration(migrations.Migration):
    dependencies = [("core", "0011_evidence_submitted_by_requirement_criticality_and_more")]
    operations = [migrations.RunPython(apply_security, remove_security)]
