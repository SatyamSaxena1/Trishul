"""Tenant-safe UCF links and active-engagement read policies."""

import os
import re

from django.db import migrations

ENGAGEMENT_FUNCTION = """
CREATE FUNCTION trishul_engagement_allows_deployment(deployment_target uuid, policy_rule uuid)
RETURNS boolean AS $$
    SELECT COALESCE(
        (
            SELECT trishul_engagement_allows(t.tenant_id, t.application_id, r.unified_control_id, false)
            FROM da_deployment_target t
            LEFT JOIN da_policy_rule r ON r.id = policy_rule AND r.tenant_id = t.tenant_id
            WHERE t.id = deployment_target
        ),
        false
    )
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
"""

RULE_FUNCTION = """
CREATE FUNCTION trishul_engagement_allows_rule(rule uuid)
RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1
        FROM da_control_result cr
        JOIN da_evaluation_run er ON er.id = cr.evaluation_run_id
        WHERE cr.policy_rule_id = rule
          AND trishul_engagement_allows_deployment(er.target_id, rule)
    )
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
"""


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
        raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
    with schema_editor.connection.cursor() as cursor:
        for child, column, parent in (
            ("da_policy_rule", "unified_control_id", "core_unifiedcontrolobjective"),
            ("da_control_result", "gap_id", "core_compliancegap"),
        ):
            constraint = f"same_tenant_{child.removeprefix('da_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(
                f"ALTER TABLE {quote(child)} ADD CONSTRAINT {quote(constraint)} "
                f"FOREIGN KEY ({quote(column)}, tenant_id) REFERENCES {quote(parent)} (id, tenant_id) "
                "DEFERRABLE INITIALLY DEFERRED"
            )

        cursor.execute("DROP FUNCTION IF EXISTS trishul_engagement_allows_deployment(uuid, uuid)")
        cursor.execute(ENGAGEMENT_FUNCTION)
        cursor.execute("DROP FUNCTION IF EXISTS trishul_engagement_allows_rule(uuid)")
        cursor.execute(RULE_FUNCTION)
        cursor.execute("REVOKE ALL ON FUNCTION trishul_engagement_allows_deployment(uuid, uuid) FROM PUBLIC")
        cursor.execute("REVOKE ALL ON FUNCTION trishul_engagement_allows_rule(uuid) FROM PUBLIC")
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        if not cursor.fetchone():
            return
        role = quote(app_role)
        cursor.execute(f"GRANT EXECUTE ON FUNCTION trishul_engagement_allows_deployment(uuid, uuid) TO {role}")
        cursor.execute(f"GRANT EXECUTE ON FUNCTION trishul_engagement_allows_rule(uuid) TO {role}")

        policies = {
            "da_deployment_target": "trishul_engagement_allows_deployment(id, NULL)",
            "da_deployment_snapshot": "trishul_engagement_allows_deployment(target_id, NULL)",
            "da_evaluation_run": "trishul_engagement_allows_deployment(target_id, NULL)",
            "da_control_result": (
                "trishul_engagement_allows_deployment("
                "(SELECT target_id FROM da_evaluation_run WHERE id = evaluation_run_id), policy_rule_id)"
            ),
            "da_deployment_decision": "trishul_engagement_allows_deployment(target_id, NULL)",
            "da_evidence_artifact": "trishul_engagement_allows_deployment(target_id, NULL)",
            "da_exception_waiver": "trishul_engagement_allows_deployment(target_id, policy_rule_id)",
            "da_drift_event": "trishul_engagement_allows_deployment(target_id, NULL)",
            "da_policy_rule": "trishul_engagement_allows_rule(id)",
            "da_control_mapping": "trishul_engagement_allows_rule(policy_rule_id)",
        }
        for table_name, expression in policies.items():
            cursor.execute(
                f"CREATE POLICY engagement_read ON {quote(table_name)} FOR SELECT TO {role} USING ({expression})"
            )


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        with schema_editor.connection.cursor() as cursor:
            cursor.execute("DROP FUNCTION IF EXISTS trishul_engagement_allows_rule(uuid)")
            cursor.execute("DROP FUNCTION IF EXISTS trishul_engagement_allows_deployment(uuid, uuid)")


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0006_saas_tenant_security"),
        ("deployment_assurance", "0003_grc_links"),
    ]
    operations = [migrations.RunPython(apply_security, remove_security)]
