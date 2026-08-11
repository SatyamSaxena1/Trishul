"""The canonical authorization facade.

Every permission check in the product goes through check()/require() here,
and every decision they make is audited via security.record_authorization_decision.
core/security.py owns the primitives (permission composition, session and
tenant resolution); this module is the single entry point views call, so
"check the permission, audit the decision, raise on denial" never gets
reimplemented per-view.

AUTHORIZATION_AUDIT_BRIDGE (temporary backwards-compatibility note):
ROLE_PERMISSIONS in core/security.py is the seeded/default atomic-permission
set for built-in roles -- it is data, not a second authorization system.
membership_permissions() is the single place that composes a membership's
built-in role grant, its ad hoc extra_permissions, and an optional CustomRole's
atomic permissions into one effective set; every caller here and in
core/security.py resolves permissions through that one function (via
principal_permissions/get_effective_permissions). If ROLE_PERMISSIONS is ever
replaced by a database-seeded permission table, membership_permissions() is
the only function that needs to change -- no call site in this module or in
views.py inspects a role name directly.
"""

from rest_framework import exceptions

from .security import has_permission, principal_permissions, record_authorization_decision


class AuthorizationDenied(exceptions.PermissionDenied):
    """Raised only by authorization.require().

    Tagging it lets a caller's handle_exception restore the transaction's
    rollback flag for *this specific, already-audited* denial without
    touching a PermissionDenied raised later in a request (e.g. mid-write,
    after real side effects have already happened), where letting the
    transaction roll back is still correct. See
    TenantModelViewSet.handle_exception in views.py for why this matters
    under Django's ATOMIC_REQUESTS.
    """


def get_effective_permissions(request) -> set[str]:
    """The composed atomic-permission set for the current request's principal."""
    return principal_permissions(request)


def check(
    request,
    permission: str,
    *,
    resource_type: str,
    resource_id="",
    application_id=None,
    target_tenant=None,
    engagement=None,
    correlation_id="",
) -> bool:
    """Evaluate one atomic permission and record the decision. Never raises."""
    allowed = has_permission(request, permission)
    record_authorization_decision(
        request,
        action=permission,
        resource_type=resource_type,
        resource_id=resource_id,
        decision="allow" if allowed else "deny",
        reason="permission_granted" if allowed else "permission_not_granted",
        target_tenant=target_tenant,
        engagement=engagement,
        application_id=application_id,
        correlation_id=correlation_id,
    )
    return allowed


def require(request, permission: str, **kwargs) -> None:
    """Like check(), but raises AuthorizationDenied when the decision is DENY."""
    if not check(request, permission, **kwargs):
        raise AuthorizationDenied("Permission is not granted for this operation.")
