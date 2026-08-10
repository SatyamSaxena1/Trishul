from contextlib import contextmanager
from contextvars import ContextVar
from uuid import UUID

from django.db import connection

_tenant_id: ContextVar[UUID | None] = ContextVar("tenant_id", default=None)


def current_tenant_id() -> UUID | None:
    return _tenant_id.get()


def set_current_tenant(tenant_id: UUID | None):
    return _tenant_id.set(tenant_id)


def reset_current_tenant(token) -> None:
    _tenant_id.reset(token)


@contextmanager
def tenant_context(tenant_id: UUID):
    token = set_current_tenant(tenant_id)
    try:
        yield
    finally:
        reset_current_tenant(token)


@contextmanager
def database_tenant_context(tenant_id: UUID):
    """Establish and always clear process and PostgreSQL tenant context.

    Celery work spans several transactions, so request-local ``set_config`` is
    insufficient there. The session setting is cleared in ``finally`` to keep
    reused worker connections from leaking a previous tenant.
    """
    with tenant_context(tenant_id):
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.tenant_id', %s, false)", [str(tenant_id)])
        try:
            yield
        finally:
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('trishul.tenant_id', '', false)")


@contextmanager
def engagement_target_context(tenant_id: UUID, engagement_id: UUID):
    """Scope ORM managers to an auditee while PostgreSQL retains firm context."""
    token = set_current_tenant(tenant_id)
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.engagement_id', %s, true)", [str(engagement_id)])
    try:
        yield
    finally:
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.engagement_id', '', true)")
        reset_current_tenant(token)
