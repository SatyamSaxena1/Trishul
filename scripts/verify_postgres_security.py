import os
import uuid
from datetime import datetime, timezone

import psycopg


def insert_tenants(cursor, rows):
    cursor.executemany(
        "INSERT INTO core_tenant (id, created_at, updated_at, version, slug, name, tenant_type, auditee_mode, "
        "isolation_tier, is_active, retention_days) VALUES (%s, %s, %s, 1, %s, %s, %s, %s, 'shared', true, 365)",
        rows,
    )


def insert_base_data(owner_dsn):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    org_a, org_b, workspace = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    audit = uuid.uuid4()
    now = datetime.now(timezone.utc)
    with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
        insert_tenants(
            cursor,
            [
                (tenant_a, now, now, f"tenant-{tenant_a}", "Tenant A", "auditee", "self_service"),
                (tenant_b, now, now, f"tenant-{tenant_b}", "Tenant B", "auditee", "self_service"),
            ],
        )
        cursor.executemany(
            "INSERT INTO core_organization (id, created_at, updated_at, version, tenant_id, name) "
            "VALUES (%s, %s, %s, 1, %s, %s)",
            [(org_a, now, now, tenant_a, "Org A"), (org_b, now, now, tenant_b, "Org B")],
        )
        cursor.execute(
            "INSERT INTO core_auditevent "
            "(id, created_at, updated_at, version, tenant_id, actor_type, actor_id, action, resource_type, "
            "resource_id, details, occurred_at, previous_hash, event_hash) "
            "VALUES (%s, %s, %s, 1, %s, 'system', 'test', 'created', 'test', 'test', '{}', %s, '', %s)",
            (audit, now, now, tenant_a, now, "0" * 64),
        )
    return tenant_a, tenant_b, org_a, org_b, workspace, audit


def verify(owner_dsn, app_dsn):
    tenant_a, _, org_a, org_b, workspace, audit = insert_base_data(owner_dsn)
    now = datetime.now(timezone.utc)
    with psycopg.connect(app_dsn) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM core_organization")
        assert cursor.fetchone()[0] == 0, "RLS must fail closed without tenant context"
        cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", (str(tenant_a),))
        cursor.execute("SELECT id FROM core_organization")
        assert cursor.fetchall() == [(org_a,)], "RLS exposed another tenant"

    try:
        with psycopg.connect(app_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", (str(tenant_a),))
            cursor.execute(
                "INSERT INTO core_workspace (id, created_at, updated_at, version, tenant_id, organization_id, name) "
                "VALUES (%s, %s, %s, 1, %s, %s, 'invalid')",
                (workspace, now, now, tenant_a, org_b),
            )
        raise AssertionError("Composite foreign key accepted a cross-tenant relationship")
    except psycopg.errors.ForeignKeyViolation:
        pass

    try:
        with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("UPDATE core_auditevent SET action='tampered' WHERE id=%s", (audit,))
        raise AssertionError("Audit trigger accepted mutation")
    except psycopg.errors.RaiseException:
        pass


def _application(cursor, tenant, now):
    """Create the organization/workspace/application chain for one tenant."""
    organization, workspace, application = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    cursor.execute(
        "INSERT INTO core_organization (id, created_at, updated_at, version, tenant_id, name) "
        "VALUES (%s, %s, %s, 1, %s, %s)",
        (organization, now, now, tenant, f"Org {organization}"),
    )
    cursor.execute(
        "INSERT INTO core_workspace (id, created_at, updated_at, version, tenant_id, organization_id, name) "
        "VALUES (%s, %s, %s, 1, %s, %s, 'Workspace')",
        (workspace, now, now, tenant, organization),
    )
    cursor.execute(
        "INSERT INTO core_application (id, created_at, updated_at, version, tenant_id, workspace_id, name, "
        "description, criticality, data_sensitivity, internet_exposed) "
        "VALUES (%s, %s, %s, 1, %s, %s, 'App', '', 3, 3, false)",
        (application, now, now, tenant, workspace),
    )
    return application


def _target(cursor, tenant, application, now, slug="t1"):
    target = uuid.uuid4()
    cursor.execute(
        "INSERT INTO da_deployment_target (id, created_at, updated_at, version, tenant_id, application_id, "
        "policy_profile_id, name, slug, provider, target_type, environment, external_id, region, criticality, "
        "data_sensitivity, internet_exposed, owner_reference, labels, state, baseline_snapshot_id, "
        "last_observed_at) VALUES (%s, %s, %s, 1, %s, %s, NULL, 'Target', %s, 'aws', 'cluster', 'production', "
        "%s, '', 3, 3, false, '', '{}', 'active', NULL, NULL)",
        (target, now, now, tenant, application, slug, f"ext-{target}"),
    )
    return target


def verify_deployment_assurance(owner_dsn, app_dsn):
    """Cross-tenant and immutability guarantees for the Deployment Assurance tables."""
    now = datetime.now(timezone.utc)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
        insert_tenants(
            cursor,
            [
                (tenant_a, now, now, f"da-{tenant_a}", "DA Tenant A", "auditee", "self_service"),
                (tenant_b, now, now, f"da-{tenant_b}", "DA Tenant B", "auditee", "self_service"),
            ],
        )
        application_a = _application(cursor, tenant_a, now)
        application_b = _application(cursor, tenant_b, now)
        target_a = _target(cursor, tenant_a, application_a, now)
        _target(cursor, tenant_b, application_b, now)
        evidence = uuid.uuid4()
        cursor.execute(
            "INSERT INTO da_evidence_artifact (id, created_at, updated_at, version, tenant_id, target_id, "
            "snapshot_id, evaluation_run_id, role, object_key, media_type, size_bytes, sha256, envelope, "
            "classification, retention_class, legal_hold) VALUES (%s, %s, %s, 1, %s, %s, NULL, NULL, "
            "'source_artifact', %s, 'application/json', 10, %s, '{}', 'confidential', 'default', false)",
            (evidence, now, now, tenant_a, target_a, f"{tenant_a}/evidence/{evidence}", "0" * 64),
        )

    # Row-level security must fail closed and must never expose another tenant.
    with psycopg.connect(app_dsn) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM da_deployment_target")
        assert cursor.fetchone()[0] == 0, "Deployment target RLS must fail closed without tenant context"
        cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", (str(tenant_a),))
        cursor.execute("SELECT id FROM da_deployment_target")
        assert cursor.fetchall() == [(target_a,)], "Deployment target RLS exposed another tenant"
        cursor.execute("SELECT count(*) FROM da_evidence_artifact")
        assert cursor.fetchone()[0] == 1, "Evidence RLS exposed the wrong row count"

    # A composite key must refuse a target owned by one tenant that points at
    # another tenant's application.
    try:
        with psycopg.connect(app_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", (str(tenant_a),))
            _target(cursor, tenant_a, application_b, now, slug="cross-tenant")
        raise AssertionError("Composite foreign key accepted a cross-tenant application reference")
    except psycopg.errors.ForeignKeyViolation:
        pass

    # Evidence is append-only, even for the table owner.
    try:
        with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("UPDATE da_evidence_artifact SET sha256 = %s", ("1" * 64,))
        raise AssertionError("Evidence immutability trigger accepted a mutation")
    except psycopg.errors.RaiseException:
        pass

    # The decision guard must exist; its content columns are protected while the
    # supersession pointer stays writable.
    with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM pg_trigger WHERE tgname = 'da_deployment_decision_immutable' AND NOT tgisinternal"
        )
        assert cursor.fetchone()[0] == 1, "Deployment decision guard trigger is missing"
        cursor.execute("SELECT prosrc FROM pg_proc WHERE proname = 'trishul_guard_decision_mutation'")
        source = cursor.fetchone()[0]
        assert "decision_hash" in source, "Decision guard does not protect the decision hash"
        assert "superseded_by" not in source, "Decision guard must leave the supersession pointer writable"


def verify_rls_catalog(owner_dsn, app_dsn):
    """Every table carrying tenant_id must be forced behind RLS."""
    with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
            WHERE n.nspname = 'public' AND c.relkind = 'r'
            ORDER BY c.relname
            """
        )
        rows = cursor.fetchall()
    assert rows, "No tenant-owned tables were found"
    insecure = [name for name, enabled, forced in rows if not (enabled and forced)]
    assert not insecure, f"Tenant tables without enabled and forced RLS: {insecure}"

    with psycopg.connect(app_dsn) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        assert cursor.fetchone() == (False, False), "Application role must not bypass RLS"


def _insert_user(cursor, username, now):
    cursor.execute(
        "INSERT INTO auth_user (password, last_login, is_superuser, username, first_name, last_name, email, "
        "is_staff, is_active, date_joined) VALUES ('', NULL, false, %s, '', '', '', false, true, %s) RETURNING id",
        (username, now),
    )
    return cursor.fetchone()[0]


def _engagement_count(app_dsn, firm, user, engagement, control):
    with psycopg.connect(app_dsn) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", (str(firm),))
        cursor.execute("SELECT set_config('trishul.user_id', %s, true)", (str(user),))
        cursor.execute("SELECT set_config('trishul.engagement_id', %s, true)", (str(engagement),))
        cursor.execute("SELECT count(*) FROM core_organisationcontrol WHERE id = %s", (control,))
        return cursor.fetchone()[0]


def verify_engagement_rls(owner_dsn, app_dsn):
    """The database itself grants auditee rows only through a live, scoped engagement."""
    now = datetime.now(timezone.utc)
    firm, auditee = uuid.uuid4(), uuid.uuid4()
    engagement, relationship, membership, engagement_member = (uuid.uuid4() for _ in range(4))
    uco, control = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
        insert_tenants(
            cursor,
            [
                (firm, now, now, f"firm-{firm}", "Audit Firm", "audit_firm", ""),
                (auditee, now, now, f"auditee-{auditee}", "Auditee", "auditee", "firm_managed"),
            ],
        )
        application = _application(cursor, auditee, now)
        auditor = _insert_user(cursor, f"auditor-{firm}", now)
        unassigned = _insert_user(cursor, f"unassigned-{firm}", now)
        cursor.executemany(
            "INSERT INTO core_membership (id, created_at, updated_at, version, tenant_id, user_id, role, "
            "extra_permissions, application_ids, is_active) "
            "VALUES (%s, %s, %s, 1, %s, %s, 'auditor', '[]', '[]', true)",
            [
                (membership, now, now, firm, auditor),
                (uuid.uuid4(), now, now, firm, unassigned),
            ],
        )
        cursor.execute(
            "INSERT INTO core_tenantrelationship (id, created_at, updated_at, version, tenant_id, "
            "related_tenant_id, relationship, status) VALUES (%s, %s, %s, 1, %s, %s, 'manages', 'active')",
            (relationship, now, now, firm, auditee),
        )
        cursor.execute(
            "INSERT INTO core_unifiedcontrolobjective (id, created_at, updated_at, version, tenant_id, code, "
            "objective_version, domain, objective, control_type, nature, approved_at) "
            "VALUES (%s, %s, %s, 1, %s, 'UCO-PG-001', '1.0', 'test', 'PostgreSQL isolation test', "
            "'preventive', 'technical', %s)",
            (uco, now, now, auditee, now),
        )
        cursor.execute(
            "INSERT INTO core_organisationcontrol (id, created_at, updated_at, version, tenant_id, application_id, "
            "unified_control_id, applicability, owner_id, status, implementation_score, maturity_level, "
            "last_reviewed_at) VALUES (%s, %s, %s, 1, %s, %s, %s, 'applicable', NULL, 'under_review', 0, 0, NULL)",
            (control, now, now, auditee, application, uco),
        )
        cursor.execute(
            "INSERT INTO core_engagement (id, created_at, updated_at, version, tenant_id, auditee_tenant_id, name, "
            "reference, status, starts_on, ends_on, framework_scope, application_scope, control_scope, created_by_id, "
            "approved_by_id, closed_reason) VALUES (%s, %s, %s, 1, %s, %s, 'Pilot audit', %s, 'active', "
            "CURRENT_DATE - 1, CURRENT_DATE + 1, '[]', %s::jsonb, '[]', %s, %s, '')",
            (engagement, now, now, firm, auditee, f"PG-{engagement}", f'["{application}"]', auditor, auditor),
        )
        cursor.execute(
            "INSERT INTO core_engagementmember (id, created_at, updated_at, version, tenant_id, engagement_id, "
            "user_id, role, framework_scope, control_scope, is_active) VALUES (%s, %s, %s, 1, %s, %s, %s, "
            "'auditor', '[]', '[]', true)",
            (engagement_member, now, now, firm, engagement, auditor),
        )

    # A relationship alone and an unassigned firm user confer no visibility.
    assert _engagement_count(app_dsn, firm, auditor, uuid.uuid4(), control) == 0
    assert _engagement_count(app_dsn, firm, unassigned, engagement, control) == 0
    assert _engagement_count(app_dsn, firm, auditor, engagement, control) == 1

    with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
        for status in ("closed", "revoked"):
            cursor.execute("UPDATE core_engagement SET status = %s WHERE id = %s", (status, engagement))
            connection.commit()
            assert _engagement_count(app_dsn, firm, auditor, engagement, control) == 0
        cursor.execute(
            "UPDATE core_engagement SET status = 'active', starts_on = CURRENT_DATE - 2, ends_on = CURRENT_DATE - 1 "
            "WHERE id = %s",
            (engagement,),
        )
        connection.commit()
        assert _engagement_count(app_dsn, firm, auditor, engagement, control) == 0

    # SET LOCAL context is cleared at transaction end on a reused connection.
    with psycopg.connect(app_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", (str(auditee),))
            cursor.execute("SELECT count(*) FROM core_organisationcontrol")
            assert cursor.fetchone()[0] == 1
        connection.commit()
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM core_organisationcontrol")
            assert cursor.fetchone()[0] == 0, "Tenant context leaked across transactions"


if __name__ == "__main__":
    verify_rls_catalog(os.environ["OWNER_DSN"], os.environ["APP_DSN"])
    verify(os.environ["OWNER_DSN"], os.environ["APP_DSN"])
    verify_deployment_assurance(os.environ["OWNER_DSN"], os.environ["APP_DSN"])
    verify_engagement_rls(os.environ["OWNER_DSN"], os.environ["APP_DSN"])
    print("PostgreSQL tenant, engagement, audit and deployment assurance controls verified")
