import os
import uuid
from datetime import datetime, timezone

import psycopg


def insert_base_data(owner_dsn):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    org_a, org_b, workspace = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    audit = uuid.uuid4()
    now = datetime.now(timezone.utc)
    with psycopg.connect(owner_dsn) as connection, connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO core_tenant (id, created_at, updated_at, version, slug, name, is_active, retention_days) "
            "VALUES (%s, %s, %s, 1, %s, %s, true, 365)",
            [
                (tenant_a, now, now, f"tenant-{tenant_a}", "Tenant A"),
                (tenant_b, now, now, f"tenant-{tenant_b}", "Tenant B"),
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


if __name__ == "__main__":
    verify(os.environ["OWNER_DSN"], os.environ["APP_DSN"])
    print("PostgreSQL tenant and audit controls verified")
