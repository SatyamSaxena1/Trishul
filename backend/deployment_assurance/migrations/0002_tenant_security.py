"""Database-level tenant isolation for Deployment Assurance.

Mirrors ``core.migrations.0002_tenant_security``. Application code filtering is
a convenience only; the guarantees below are enforced by PostgreSQL:

* row-level security, forced even for the table owner, on every tenant table;
* composite ``(id, tenant_id)`` foreign keys so a child row can never reference
  a parent belonging to another tenant, including across the ``core`` app;
* least-privilege grants for the unprivileged application role.
"""

import os
import re

from django.db import migrations

# (child table, column, parent table). Parents in ``core`` already carry their
# ``(id, tenant_id)`` unique constraint from core migration 0002.
RELATIONSHIPS = [
    ("da_deployment_target", "application_id", "core_application"),
    ("da_deployment_target", "policy_profile_id", "da_policy_profile"),
    ("da_deployment_snapshot", "target_id", "da_deployment_target"),
    ("da_deployment_snapshot", "supersedes_id", "da_deployment_snapshot"),
    ("da_policy_rule", "policy_pack_id", "da_policy_pack"),
    ("da_policy_profile", "policy_pack_id", "da_policy_pack"),
    ("da_policy_profile", "threshold_profile_id", "da_threshold_profile"),
    ("da_control_mapping", "policy_rule_id", "da_policy_rule"),
    ("da_evaluation_run", "snapshot_id", "da_deployment_snapshot"),
    ("da_evaluation_run", "target_id", "da_deployment_target"),
    ("da_evaluation_run", "policy_pack_id", "da_policy_pack"),
    ("da_evaluation_run", "policy_profile_id", "da_policy_profile"),
    ("da_control_result", "evaluation_run_id", "da_evaluation_run"),
    ("da_control_result", "policy_rule_id", "da_policy_rule"),
    ("da_control_result", "waived_by_id", "da_exception_waiver"),
    ("da_control_result", "risk_id", "core_risk"),
    ("da_evidence_artifact", "target_id", "da_deployment_target"),
    ("da_evidence_artifact", "snapshot_id", "da_deployment_snapshot"),
    ("da_evidence_artifact", "evaluation_run_id", "da_evaluation_run"),
    ("da_exception_waiver", "target_id", "da_deployment_target"),
    ("da_exception_waiver", "policy_rule_id", "da_policy_rule"),
    ("da_deployment_decision", "evaluation_run_id", "da_evaluation_run"),
    ("da_deployment_decision", "target_id", "da_deployment_target"),
    ("da_deployment_decision", "threshold_profile_id", "da_threshold_profile"),
    ("da_deployment_decision", "superseded_by_id", "da_deployment_decision"),
    ("da_drift_event", "target_id", "da_deployment_target"),
    ("da_drift_event", "baseline_snapshot_id", "da_deployment_snapshot"),
    ("da_drift_event", "observed_snapshot_id", "da_deployment_snapshot"),
    ("da_drift_event", "evaluation_run_id", "da_evaluation_run"),
]

# Parent tables owned by this app that need a composite unique key.
LOCAL_PARENTS = sorted({parent for _, _, parent in RELATIONSHIPS if parent.startswith("da_")})

# Evidence is a pure append-only record of fact: never updated, never deleted.
APPEND_ONLY_TABLES = ("da_evidence_artifact",)

# A decision's content is immutable, but its lifecycle pointer is not: a later
# evaluation must be able to mark an earlier decision superseded. The trigger
# below therefore permits exactly that column to change and rejects everything
# else, rather than locking the row outright.
DECISION_TABLE = "da_deployment_decision"
DECISION_PROTECTED_COLUMNS = (
    "id",
    "tenant_id",
    "evaluation_run_id",
    "target_id",
    "threshold_profile_id",
    "decision",
    "compliance_score",
    "risk_score",
    "reason_codes",
    "counts",
    "decision_hash",
    "finalized_at",
    "created_at",
)


REJECT_MUTATION_SQL = (
    "CREATE FUNCTION trishul_reject_deployment_mutation() RETURNS trigger AS $$ "
    "BEGIN RAISE EXCEPTION 'deployment assurance evidence is immutable'; END; "
    "$$ LANGUAGE plpgsql"
)

GUARD_DECISION_SQL = """
CREATE FUNCTION trishul_guard_decision_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'deployment decisions cannot be deleted';
    END IF;
    IF {comparison} THEN
        RAISE EXCEPTION 'deployment decision content is immutable; only supersession may be recorded';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
"""


def apply_security(apps, schema_editor):
    # SQLite has neither row-level security nor PL/pgSQL. Development and the
    # test suite therefore rely on the ORM-level tenant manager; the PostgreSQL
    # guarantees below are what production depends on, and the cross-tenant
    # tests are run against PostgreSQL in CI.
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    tenant_expression = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    tenant_tables = []
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(REJECT_MUTATION_SQL)
        cursor.execute(
            GUARD_DECISION_SQL.format(
                comparison=" OR ".join(
                    f"NEW.{column} IS DISTINCT FROM OLD.{column}" for column in DECISION_PROTECTED_COLUMNS
                )
            )
        )
        for model in apps.get_app_config("deployment_assurance").get_models():
            if "tenant" not in {field.name for field in model._meta.fields}:
                continue
            table = quote(model._meta.db_table)
            tenant_tables.append(model._meta.db_table)
            cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            cursor.execute(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING ({tenant_expression}) WITH CHECK ({tenant_expression})"
            )

        for parent in LOCAL_PARENTS:
            constraint = f"{parent}_id_tenant_uniq"[:63]
            cursor.execute(f"ALTER TABLE {quote(parent)} ADD CONSTRAINT {quote(constraint)} UNIQUE (id, tenant_id)")
        for child, column, parent in RELATIONSHIPS:
            constraint = f"same_tenant_{child.removeprefix('da_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(
                f"ALTER TABLE {quote(child)} ADD CONSTRAINT {quote(constraint)} "
                f"FOREIGN KEY ({quote(column)}, tenant_id) REFERENCES {quote(parent)} (id, tenant_id) "
                "DEFERRABLE INITIALLY DEFERRED"
            )

        for table_name in APPEND_ONLY_TABLES:
            cursor.execute(
                f"CREATE TRIGGER {quote(table_name + '_immutable')} BEFORE UPDATE OR DELETE ON {quote(table_name)} "
                "FOR EACH ROW EXECUTE FUNCTION trishul_reject_deployment_mutation()"
            )
        cursor.execute(
            f"CREATE TRIGGER {quote(DECISION_TABLE + '_immutable')} BEFORE UPDATE OR DELETE "
            f"ON {quote(DECISION_TABLE)} FOR EACH ROW EXECUTE FUNCTION trishul_guard_decision_mutation()"
        )

        app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
            raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        if cursor.fetchone():
            role = quote(app_role)
            for table_name in tenant_tables:
                if table_name in APPEND_ONLY_TABLES:
                    privileges = "SELECT, INSERT"
                elif table_name == DECISION_TABLE:
                    # UPDATE is permitted only so far as the trigger allows.
                    privileges = "SELECT, INSERT, UPDATE"
                else:
                    privileges = "SELECT, INSERT, UPDATE, DELETE"
                cursor.execute(f"GRANT {privileges} ON {quote(table_name)} TO {role}")


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    with schema_editor.connection.cursor() as cursor:
        for table_name in (*APPEND_ONLY_TABLES, DECISION_TABLE):
            cursor.execute(f"DROP TRIGGER IF EXISTS {quote(table_name + '_immutable')} ON {quote(table_name)}")
        cursor.execute("DROP FUNCTION IF EXISTS trishul_reject_deployment_mutation() CASCADE")
        cursor.execute("DROP FUNCTION IF EXISTS trishul_guard_decision_mutation() CASCADE")


class Migration(migrations.Migration):
    dependencies = [("deployment_assurance", "0001_initial"), ("core", "0004_job_application")]
    operations = [migrations.RunPython(apply_security, remove_security)]
