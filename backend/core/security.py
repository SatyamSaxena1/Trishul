import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.utils import timezone
from rest_framework import authentication, exceptions

from .dev_auth import PERSONA_USERNAMES
from .models import (
    AuditEvent,
    AuthSession,
    BreakGlassGrant,
    IdentityProviderConfiguration,
    Membership,
    ServiceAccount,
    TenantSessionPolicy,
)
from .tenancy import set_current_tenant

logger = logging.getLogger(__name__)

BREAK_GLASS_PERMISSIONS = {
    "tenant.read",
    "application.read",
    "control.read",
    "evidence.read",
    "risk.read",
    "task.read",
    "report.read",
    "audit.read",
}

ROLE_PERMISSIONS = {
    "admin": {"*"},
    "platform_admin": {
        "platform.manage",
        "tenant.read",
        "subscription.read",
        "subscription.manage",
        "usage.read",
        "audit.read",
    },
    "firm_admin": {
        "tenant.manage",
        "membership.manage",
        "membership.read",
        "branding.read",
        "branding.manage",
        "engagement.read",
        "engagement.manage",
        "subscription.read",
        "usage.read",
        "audit.read",
    },
    "audit_manager": {
        "tenant.read",
        "engagement.read",
        "engagement.manage",
        "engagement.review",
        "usage.read",
        "audit.read",
    },
    "reviewer": {"engagement.read", "engagement.review", "audit.read"},
    "org_admin": {
        "tenant.manage",
        "membership.manage",
        "membership.read",
        "application.read",
        "application.write",
        "control.read",
        "evidence.read",
        "subscription.read",
        "usage.read",
        "audit.read",
    },
    "compliance_manager": {
        "application.read",
        "application.write",
        "control.read",
        "control.manage",
        "assessment.read",
        "assessment.write",
        "evidence.read",
        "risk.read",
        "task.read",
        "task.manage",
        "usage.read",
    },
    "control_owner": {"control.assigned", "evidence.assigned", "task.assigned"},
    "risk_owner": {"risk.read", "risk.accept", "task.read", "task.manage"},
    "vendor_manager": {"vendor.manage", "risk.read", "evidence.read", "task.read", "task.manage"},
    "ciso": {
        "application.read",
        "control.read",
        "finding.read",
        "evidence.read",
        "threat_model.read",
        "assessment.read",
        "risk.read",
        "task.read",
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
        "engagement.read",
        "engagement.review",
        "engagement.verdict",
    },
    "executive": {"application.read", "risk.read", "report.read"},
}


def _extend_role_permissions():
    """Fold optional module permission grants into the role table.

    Modules own their own permission vocabulary; ``core`` owns the role mapping.
    Importing lazily keeps ``core`` free of a hard dependency on a module that a
    given deployment may not install.
    """
    try:
        from deployment_assurance.permissions import ROLE_GRANTS
    except ImportError:  # pragma: no cover - module not installed
        return
    for role, granted in ROLE_GRANTS.items():
        if role in ROLE_PERMISSIONS and "*" not in ROLE_PERMISSIONS[role]:
            ROLE_PERMISSIONS[role] = ROLE_PERMISSIONS[role] | set(granted)


_extend_role_permissions()


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


class DevAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        username = request.headers.get("X-Trishul-Dev-User")
        if not username:
            return None
        if not settings.TRISHUL_DEV_AUTH or username not in PERSONA_USERNAMES:
            raise exceptions.AuthenticationFailed("Development identity is unavailable.")
        user = get_user_model().objects.filter(username=username, is_active=True).first()
        if not user or not Membership.all_objects.filter(user=user, is_active=True, tenant__is_active=True).exists():
            raise exceptions.AuthenticationFailed("Development persona has not been seeded.")
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.user_id', %s, true)", [str(user.id)])
        return user, {"dev_auth": True}


class OIDCBearerAuthentication(authentication.BaseAuthentication):
    _jwks_clients = {}

    @classmethod
    def _configuration(cls, token, request):
        unverified = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        requested_tenant = request.headers.get("X-Trishul-Tenant")
        if requested_tenant:
            try:
                requested_tenant = UUID(requested_tenant)
            except ValueError as exc:
                raise exceptions.AuthenticationFailed("Invalid tenant selector.") from exc
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(requested_tenant)])
        audiences = unverified.get("aud", [])
        audiences = {audiences} if isinstance(audiences, str) else set(audiences)
        configured = list(
            IdentityProviderConfiguration.all_objects.filter(
                protocol=IdentityProviderConfiguration.Protocol.OIDC,
                enabled=True,
                issuer=unverified.get("iss", ""),
                tenant__is_active=True,
                **({"tenant_id": requested_tenant} if requested_tenant else {}),
            ).select_related("tenant")
        )
        matches = [item for item in configured if item.audience in audiences]
        if len(matches) > 1:
            raise exceptions.AuthenticationFailed("Identity configuration is ambiguous.")
        return matches[0] if matches else None

    @staticmethod
    def _enforce_session(configuration, user, token, claims):
        now = timezone.now()
        policy = TenantSessionPolicy.objects.filter(tenant=configuration.tenant).first()
        if policy is None:
            policy = TenantSessionPolicy(tenant=configuration.tenant)
        digest = hashlib.sha256(token.encode()).hexdigest()
        idle_cutoff = now - timedelta(minutes=policy.idle_timeout_minutes)
        with transaction.atomic():
            session = AuthSession.objects.select_for_update().filter(token_hash=digest).first()
            if session:
                if session.revoked_at or session.absolute_expires_at <= now or session.last_seen_at <= idle_cutoff:
                    raise exceptions.AuthenticationFailed("Session has expired or been revoked.")
                AuthSession.objects.filter(pk=session.pk).update(last_seen_at=now)
                return session
            active = list(
                AuthSession.objects.select_for_update()
                .filter(user=user, revoked_at__isnull=True)
                .order_by("started_at")
            )
            active = [item for item in active if item.absolute_expires_at > now and item.last_seen_at > idle_cutoff]
            for oldest in active[: max(0, len(active) - policy.max_concurrent_sessions + 1)]:
                oldest.revoked_at = now
                oldest.save(update_fields=["revoked_at", "updated_at"])
                AuditEvent.append(
                    tenant=configuration.tenant,
                    actor_type="system",
                    actor_id="session-policy",
                    action="session.concurrent_limit_revoked",
                    resource_type="core.authsession",
                    resource_id=oldest.id,
                    details={"reason": "max_concurrent_sessions"},
                )
            token_expiry = datetime.fromtimestamp(claims["exp"], tz=UTC)
            session = AuthSession.objects.create(
                tenant=configuration.tenant,
                user=user,
                token_hash=digest,
                absolute_expires_at=min(token_expiry, now + timedelta(minutes=policy.absolute_timeout_minutes)),
            )
            AuditEvent.append(
                tenant=configuration.tenant,
                actor_type="user",
                actor_id=str(user.id),
                action="session.started",
                resource_type="core.authsession",
                resource_id=session.id,
                details={"absolute_expires_at": session.absolute_expires_at.isoformat()},
            )
            return session

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode()
        if not header.startswith("Bearer ") or header.startswith("Bearer trishul."):
            return None
        token = header.split(" ", 1)[1]
        try:
            configuration = self._configuration(token, request)
            issuer = configuration.issuer if configuration else settings.OIDC_ISSUER
            audience = configuration.audience if configuration else settings.OIDC_AUDIENCE
            jwks_url = configuration.jwks_url if configuration else settings.OIDC_JWKS_URL
            if not all((issuer, audience, jwks_url)):
                raise exceptions.AuthenticationFailed("OIDC is not configured.")
            client = self.__class__._jwks_clients.setdefault(
                jwks_url, jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300)
            )
            signing_key = client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                audience=audience,
                issuer=issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            logger.warning("OIDC token validation failed: %s", type(exc).__name__)
            raise exceptions.AuthenticationFailed("Invalid identity token.") from exc
        policy_requires_mfa = (
            TenantSessionPolicy.objects.filter(tenant=configuration.tenant)
            .values_list("require_mfa", flat=True)
            .first()
            if configuration
            else False
        )
        mfa_required = (
            configuration.mfa_required or policy_requires_mfa
            if configuration
            else settings.OIDC_MFA_REQUIRED
        )
        allowed_acr = set(configuration.allowed_acr_values) if configuration else settings.OIDC_MFA_ACR_VALUES
        if mfa_required:
            amr = set(claims.get("amr", []))
            acr = claims.get("acr", "")
            if "mfa" not in amr and acr not in allowed_acr:
                raise exceptions.AuthenticationFailed("MFA-authenticated identity is required.")
        subject = claims["sub"]
        user, _ = get_user_model().objects.update_or_create(
            username=subject[:150],
            defaults={"email": claims.get("email", "")[:254], "is_active": True},
        )
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.user_id', %s, true)", [str(user.id)])
        if configuration:
            claims["trishul_tenant_id"] = str(configuration.tenant_id)
            self._enforce_session(configuration, user, token, claims)
        return user, claims


def resolve_tenant(request):
    if isinstance(request.user, ServicePrincipal):
        request.membership = None
        tenant = request.user.account.tenant
    else:
        requested = request.headers.get("X-Trishul-Tenant")
        grant_id = request.headers.get("X-Trishul-Break-Glass")
        if grant_id:
            try:
                tenant_id, grant_uuid = UUID(requested or ""), UUID(grant_id)
            except ValueError as exc:
                raise exceptions.AuthenticationFailed("Invalid break-glass context.") from exc
            set_current_tenant(tenant_id)
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])
            now = timezone.now()
            grant = BreakGlassGrant.objects.filter(
                pk=grant_uuid,
                requester=request.user,
                status=BreakGlassGrant.Status.APPROVED,
                approved_at__isnull=False,
                revoked_at__isnull=True,
                starts_at__lte=now,
                expires_at__gt=now,
            ).select_related("tenant").first()
            if not grant or not set(grant.scopes).issubset(BREAK_GLASS_PERMISSIONS):
                raise exceptions.PermissionDenied("Break-glass access is unavailable.")
            request.membership = None
            request.break_glass_grant = grant
            request.tenant = grant.tenant
            AuditEvent.append(
                tenant=grant.tenant,
                actor_type="user",
                actor_id=str(request.user.id),
                action="break_glass.used",
                resource_type="http.request",
                resource_id=request.path[:200],
                details={"grant_id": str(grant.id), "reason": grant.reason},
            )
            return grant.tenant
        memberships = Membership.all_objects.filter(
            user=request.user, is_active=True, tenant__is_active=True
        ).select_related("tenant")
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
        identity_tenant = request.auth.get("trishul_tenant_id") if isinstance(request.auth, dict) else None
        if identity_tenant and str(tenant.id) != identity_tenant:
            raise exceptions.PermissionDenied("The identity provider does not authorize the selected tenant.")
    set_current_tenant(tenant.id)
    request.tenant = tenant
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant.id)])
    return tenant


def principal_permissions(request) -> set[str]:
    if isinstance(request.user, ServicePrincipal):
        return set(request.user.account.scopes)
    if grant := getattr(request, "break_glass_grant", None):
        return set(grant.scopes)
    membership = request.membership
    return ROLE_PERMISSIONS.get(membership.role, set()) | set(membership.extra_permissions)


def has_permission(request, permission: str) -> bool:
    permissions = principal_permissions(request)
    if "*" not in permissions and permission not in permissions:
        return False
    application_id = getattr(request, "application_id", None)
    if getattr(request, "break_glass_grant", None):
        restrictions = []
    else:
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
