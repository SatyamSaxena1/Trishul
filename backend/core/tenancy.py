from contextlib import contextmanager
from contextvars import ContextVar
from uuid import UUID

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
