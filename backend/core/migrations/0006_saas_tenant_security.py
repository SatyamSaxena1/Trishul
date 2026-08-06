"""RLS, relationship integrity and immutability for the SaaS/UCF slice."""

import os
import re

from django.db import migrations

TENANT_TABLES = (
    "core_assessmentobservation",
    "core_auditorverdict",
    "core_controlassignment",
    "core_controlevidencelink",
    "core_crosstenantaccessevent",
    "core_engagement",
    "core_engagementmember",
    "core_engagementscope",
    "core_engagementstatushistory",
    "core_evidencerequirement",
    "core_framework",
    "core_frameworkcontrolmapping",
    "core_organisationcontrol",
    "core_subscriptionplan",
    "core_task",
    "core_tenantbranding",
    "core_tenantentitlement",
    "core_tenantinvitation",
    "core_tenantrelationship",
    "core_tenantsubscription",
    "core_unifiedcontrolobjective",
    "core_usagerecord",
)

RELATIONSHIPS = (
    ("core_assessmentobservation", "assessment_id", "core_assessment"),
    ("core_assessmentobservation", "organisation_control_id", "core_organisationcontrol"),
    ("core_auditorverdict", "organisation_control_id", "core_organisationcontrol"),
    ("core_auditorverdict", "supersedes_id", "core_auditorverdict"),
    ("core_controlassignment", "organisation_control_id", "core_organisationcontrol"),
    ("core_controlevidencelink", "organisation_control_id", "core_organisationcontrol"),
    ("core_controlevidencelink", "evidence_id", "core_evidence"),
    ("core_crosstenantaccessevent", "engagement_id", "core_engagement"),
    ("core_engagementmember", "engagement_id", "core_engagement"),
    ("core_engagementscope", "engagement_id", "core_engagement"),
    ("core_engagementstatushistory", "engagement_id", "core_engagement"),
    ("core_evidencerequirement", "unified_control_id", "core_unifiedcontrolobjective"),
    ("core_frameworkcontrolmapping", "requirement_id", "core_requirement"),
    ("core_frameworkcontrolmapping", "unified_control_id", "core_unifiedcontrolobjective"),
    ("core_frameworkversion", "framework_record_id", "core_framework"),
    ("core_organisationcontrol", "application_id", "core_application"),
    ("core_organisationcontrol", "unified_control_id", "core_unifiedcontrolobjective"),
    ("core_task", "gap_id", "core_compliancegap"),
    ("core_task", "organisation_control_id", "core_organisationcontrol"),
    ("core_task", "risk_id", "core_risk"),
    ("core_compliancegap", "organisation_control_id", "core_organisationcontrol"),
    ("core_evidence", "supersedes_id", "core_evidence"),
    ("core_remediation", "gap_id", "core_compliancegap"),
)

IMMUTABLE_TABLES = (
    "core_assessmentobservation",
    "core_auditorverdict",
    "core_controlevidencelink",
    "core_crosstenantaccessevent",
    "core_engagementstatushistory",
    "core_evidence",
)

ENGAGEMENT_FUNCTION = """
CREATE FUNCTION trishul_engagement_allows(
    target_tenant uuid, application uuid, unified_control uuid, wants_write boolean
) RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1
        FROM core_engagement e
        JOIN core_membership m
          ON m.tenant_id = e.tenant_id
         AND m.user_id = NULLIF(current_setting('trishul.user_id', true), '')::integer
         AND m.is_active
        LEFT JOIN core_engagementmember em
          ON em.engagement_id = e.id
         AND em.tenant_id = e.tenant_id
         AND em.user_id = m.user_id
         AND em.is_active
        LEFT JOIN core_unifiedcontrolobjective uco
          ON uco.id = unified_control AND uco.tenant_id = target_tenant
        WHERE e.id = NULLIF(current_setting('trishul.engagement_id', true), '')::uuid
          AND e.tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid
          AND e.auditee_tenant_id = target_tenant
          AND e.status = 'active'
          AND CURRENT_DATE BETWEEN e.starts_on AND e.ends_on
          AND (m.role IN ('firm_admin', 'audit_manager') OR em.id IS NOT NULL)
          AND (NOT wants_write OR m.role = 'audit_manager' OR em.role IN ('lead', 'auditor'))
          AND (e.application_scope = '[]'::jsonb OR (application IS NOT NULL AND e.application_scope ? application::text))
          AND (e.control_scope = '[]'::jsonb OR (uco.id IS NOT NULL AND e.control_scope ? uco.code))
    )
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
"""


def apply_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    tenant_expression = "tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid"
    app_role = os.getenv("TRISHUL_APP_DB_ROLE", "trishul_app")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", app_role):
        raise RuntimeError("TRISHUL_APP_DB_ROLE is not a valid PostgreSQL role name")
    with schema_editor.connection.cursor() as cursor:
        for table_name in TENANT_TABLES:
            table = quote(table_name)
            cursor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            cursor.execute(
                f"CREATE POLICY tenant_isolation ON {table} USING ({tenant_expression}) WITH CHECK ({tenant_expression})"
            )

        # ``ComplianceGap`` only became a composite-FK parent in this release;
        # older parents already received their key in core.0002.
        parents = {
            parent
            for _, _, parent in RELATIONSHIPS
            if parent in TENANT_TABLES or parent == "core_compliancegap"
        }
        for parent in parents:
            constraint = f"{parent}_id_tenant_uniq"[:63]
            cursor.execute(f"ALTER TABLE {quote(parent)} ADD CONSTRAINT {quote(constraint)} UNIQUE (id, tenant_id)")
        for child, column, parent in RELATIONSHIPS:
            constraint = f"same_tenant_{child.removeprefix('core_')}_{column.removesuffix('_id')}"[:63]
            cursor.execute(
                f"ALTER TABLE {quote(child)} ADD CONSTRAINT {quote(constraint)} "
                f"FOREIGN KEY ({quote(column)}, tenant_id) REFERENCES {quote(parent)} (id, tenant_id) "
                "DEFERRABLE INITIALLY DEFERRED"
            )

        for table_name in IMMUTABLE_TABLES:
            cursor.execute(
                f"CREATE TRIGGER {quote(table_name + '_immutable')} BEFORE UPDATE OR DELETE ON {quote(table_name)} "
                "FOR EACH ROW EXECUTE FUNCTION trishul_reject_audit_mutation()"
            )

        cursor.execute("DROP FUNCTION IF EXISTS trishul_engagement_allows(uuid, uuid, uuid, boolean)")
        cursor.execute(ENGAGEMENT_FUNCTION)
        cursor.execute("REVOKE ALL ON FUNCTION trishul_engagement_allows(uuid, uuid, uuid, boolean) FROM PUBLIC")

        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [app_role])
        if cursor.fetchone():
            role = quote(app_role)
            cursor.execute(f"GRANT EXECUTE ON FUNCTION trishul_engagement_allows(uuid, uuid, uuid, boolean) TO {role}")
            cursor.execute(
                f"CREATE POLICY platform_or_firm_tenant_create ON core_tenant FOR INSERT TO {role} WITH CHECK ("
                "EXISTS (SELECT 1 FROM core_membership m WHERE "
                "m.tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid "
                "AND m.user_id = NULLIF(current_setting('trishul.user_id', true), '')::integer AND m.is_active "
                "AND ((m.role = 'platform_admin' AND tenant_type = 'audit_firm') "
                "OR (m.role IN ('firm_admin', 'audit_manager') AND tenant_type = 'auditee'))))"
            )
            cursor.execute(
                f"CREATE POLICY platform_tenant_update ON core_tenant FOR UPDATE TO {role} USING ("
                "EXISTS (SELECT 1 FROM core_membership m WHERE "
                "m.tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid "
                "AND m.user_id = NULLIF(current_setting('trishul.user_id', true), '')::integer "
                "AND m.is_active AND m.role = 'platform_admin'))"
            )
            cursor.execute(f"GRANT INSERT, UPDATE ON core_tenant TO {role}")

            delegated = (
                "EXISTS (SELECT 1 FROM core_membership m JOIN core_tenant target ON target.id = tenant_id WHERE "
                "m.tenant_id = NULLIF(current_setting('trishul.tenant_id', true), '')::uuid "
                "AND m.user_id = NULLIF(current_setting('trishul.user_id', true), '')::integer AND m.is_active "
                "AND ((m.role = 'platform_admin' AND target.tenant_type = 'audit_firm') "
                "OR (m.role IN ('firm_admin', 'audit_manager') AND target.tenant_type = 'auditee')))"
            )
            for table_name in (
                "core_tenantsubscription",
                "core_tenantentitlement",
                "core_organization",
                "core_workspace",
            ):
                cursor.execute(
                    f"CREATE POLICY delegated_onboarding ON {quote(table_name)} FOR INSERT TO {role} WITH CHECK ({delegated})"
                )

            cursor.execute(
                f"CREATE POLICY engagement_control_select ON core_organisationcontrol FOR SELECT TO {role} USING ("
                "trishul_engagement_allows(tenant_id, application_id, unified_control_id, false))"
            )
            cursor.execute(
                f"CREATE POLICY engagement_control_update ON core_organisationcontrol FOR UPDATE TO {role} USING ("
                "trishul_engagement_allows(tenant_id, application_id, unified_control_id, true))"
            )
            cursor.execute(
                f"CREATE POLICY engagement_verdict_select ON core_auditorverdict FOR SELECT TO {role} USING ("
                "trishul_engagement_allows(tenant_id, "
                "(SELECT application_id FROM core_organisationcontrol WHERE id = organisation_control_id), "
                "(SELECT unified_control_id FROM core_organisationcontrol WHERE id = organisation_control_id), false))"
            )
            cursor.execute(
                f"CREATE POLICY engagement_verdict_insert ON core_auditorverdict FOR INSERT TO {role} WITH CHECK ("
                "engagement_id = NULLIF(current_setting('trishul.engagement_id', true), '')::uuid AND "
                "trishul_engagement_allows(tenant_id, "
                "(SELECT application_id FROM core_organisationcontrol WHERE id = organisation_control_id), "
                "(SELECT unified_control_id FROM core_organisationcontrol WHERE id = organisation_control_id), true))"
            )

            for table_name in TENANT_TABLES:
                privileges = "SELECT, INSERT" if table_name in IMMUTABLE_TABLES else "SELECT, INSERT, UPDATE, DELETE"
                cursor.execute(f"GRANT {privileges} ON {quote(table_name)} TO {role}")


def remove_security(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    quote = schema_editor.connection.ops.quote_name
    with schema_editor.connection.cursor() as cursor:
        for table_name in IMMUTABLE_TABLES:
            cursor.execute(f"DROP TRIGGER IF EXISTS {quote(table_name + '_immutable')} ON {quote(table_name)}")
        cursor.execute("DROP FUNCTION IF EXISTS trishul_engagement_allows(uuid, uuid, uuid, boolean)")


class Migration(migrations.Migration):
    dependencies = [("core", "0005_saas_ucf_foundation")]
    operations = [migrations.RunPython(apply_security, remove_security)]
