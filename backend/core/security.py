import hashlib
import hmac
import logging
from dataclasses import dataclass
from uuid import UUID

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection
from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import Membership, ServiceAccount
from .tenancy import set_current_tenant

logger = logging.getLogger(__name__)

ROLE_PERMISSIONS = {
    "admin": {"*"},
    "ciso": {
        "application.read",
        "finding.read",
        "evidence.read",
        "threat_model.read",
        "assessment.read",
        "risk.read",
        "risk.accept",
        "approval.decide",
        "report.create",
        "report.read",
        "report.export",
        "audit.read",
    },
    "architect": {
        "application.read",
        "finding.read",
        "evidence.read",
        "threat_model.read",
        "threat_model.write",
        "threat_model.review",
        "risk.read",
        "report.read",
    },
    "appsec": {
        "application.read",
        "repository.read",
        "repository.import",
        "scan.read",
        "scan.create",
        "scan.cancel",
        "finding.read",
        "finding.triage",
        "finding.remediate",
        "finding.suppress",
        "evidence.read",
        "risk.read",
        "report.read",
    },
    "assessor": {
        "application.read",
        "assessment.read",
        "assessment.write",
        "assessment.review",
        "evidence.read",
        "risk.read",
        "report.read",
    },
    "developer": {"application.read", "repository.read", "scan.read", "finding.read", "finding.remediate", "risk.read"},
    "manager": {"application.read", "finding.read", "evidence.read", "risk.read", "approval.request", "report.read"},
    "auditor": {
        "application.read",
        "finding.read",
        "evidence.read",
        "threat_model.read",
        "assessment.read",
        "risk.read",
        "report.read",
        "audit.read",
        "audit.export",
    },
    "executive": {"application.read", "risk.read", "report.read"},
}


@dataclass
class ServicePrincipal:
    account: ServiceAccount

    @property
    def is_authenticated(self):
        return True

    @property
    def id(self):
        return self.account.id

    @property
    def username(self):
        return self.account.name


class ServiceTokenAuthentication(authentication.BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode()
        if not header.startswith(f"{self.keyword} trishul."):
            return None
        token = header.split(" ", 1)[1]
        parts = token.split(".")
        if len(parts) != 3:
            raise exceptions.AuthenticationFailed("Invalid service token.")
        try:
            account_id = UUID(parts[1])
        except ValueError as exc:
            raise exceptions.AuthenticationFailed("Invalid service token.") from exc
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.service_account_id', %s, true)", [str(account_id)])
        account = ServiceAccount.all_objects.filter(id=account_id).select_related("tenant").first()
        digest = hashlib.sha256(token.encode()).hexdigest()
        if (
            not account
            or not hmac.compare_digest(account.token_hash, digest)
            or account.revoked_at
            or account.expires_at <= timezone.now()
            or not account.tenant.is_active
        ):
            raise exceptions.AuthenticationFailed("Invalid or expired service token.")
        ServiceAccount.all_objects.filter(pk=account.pk).update(last_used_at=timezone.now())
        return ServicePrincipal(account), account


class OIDCBearerAuthentication(authentication.BaseAuthentication):
    _jwks_client = None

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode()
        if not header.startswith("Bearer ") or header.startswith("Bearer trishul."):
            return None
        if not all([settings.OIDC_ISSUER, settings.OIDC_AUDIENCE, settings.OIDC_JWKS_URL]):
            raise exceptions.AuthenticationFailed("OIDC is not configured.")
        token = header.split(" ", 1)[1]
        try:
            if self.__class__._jwks_client is None:
                self.__class__._jwks_client = jwt.PyJWKClient(settings.OIDC_JWKS_URL, cache_jwk_set=True, lifespan=300)
            signing_key = self.__class__._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                audience=settings.OIDC_AUDIENCE,
                issuer=settings.OIDC_ISSUER,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            logger.warning("OIDC token validation failed: %s", type(exc).__name__)
            raise exceptions.AuthenticationFailed("Invalid identity token.") from exc
        if settings.OIDC_MFA_REQUIRED:
            amr = set(claims.get("amr", []))
            acr = claims.get("acr", "")
            if "mfa" not in amr and acr not in settings.OIDC_MFA_ACR_VALUES:
                raise exceptions.AuthenticationFailed("MFA-authenticated identity is required.")
        subject = claims["sub"]
        user, _ = get_user_model().objects.update_or_create(
            username=subject[:150],
            defaults={"email": claims.get("email", "")[:254], "is_active": True},
        )
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.user_id', %s, true)", [str(user.id)])
        return user, claims


def resolve_tenant(request):
    if isinstance(request.user, ServicePrincipal):
        request.membership = None
        tenant = request.user.account.tenant
    else:
        memberships = Membership.all_objects.filter(
            user=request.user, is_active=True, tenant__is_active=True
        ).select_related("tenant")
        requested = request.headers.get("X-Trishul-Tenant")
        if requested:
            try:
                tenant_id = UUID(requested)
            except ValueError as exc:
                raise exceptions.AuthenticationFailed("Invalid tenant selector.") from exc
            membership = memberships.filter(tenant_id=tenant_id).first()
            if not membership:
                raise exceptions.PermissionDenied("No membership for the selected tenant.")
        else:
            found = list(memberships[:2])
            if not found:
                raise exceptions.PermissionDenied("No active tenant membership.")
            if len(found) > 1:
                raise exceptions.ValidationError(
                    {"tenant": "X-Trishul-Tenant is required for users with multiple memberships."}
                )
            membership = found[0]
        request.membership = membership
        tenant = membership.tenant
    set_current_tenant(tenant.id)
    request.tenant = tenant
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant.id)])
    return tenant


def principal_permissions(request) -> set[str]:
    if isinstance(request.user, ServicePrincipal):
        return set(request.user.account.scopes)
    membership = request.membership
    return ROLE_PERMISSIONS.get(membership.role, set()) | set(membership.extra_permissions)


def has_permission(request, permission: str) -> bool:
    permissions = principal_permissions(request)
    if "*" not in permissions and permission not in permissions:
        return False
    application_id = getattr(request, "application_id", None)
    restrictions = (
        request.user.account.application_ids
        if isinstance(request.user, ServicePrincipal)
        else request.membership.application_ids
    )
    return not restrictions or not application_id or str(application_id) in restrictions


class TenantContextCleanupMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        set_current_tenant(None)
        try:
            return self.get_response(request)
        finally:
            set_current_tenant(None)
