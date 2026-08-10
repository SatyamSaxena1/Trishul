"""Small server-side entitlement and usage boundary for the SaaS slice."""

from django.db.models import Sum
from django.utils import timezone

from .models import TenantEntitlement, TenantSubscription, UsageRecord

MONTHLY_METRICS = frozenset({"deployment_evaluations", "ai_credits", "vendor_campaigns"})


class EntitlementDenied(RuntimeError):
    pass


def _subscription(tenant):
    return TenantSubscription.all_objects.filter(tenant=tenant).order_by("-created_at").first()


def _usable(subscription, now):
    if subscription.state == TenantSubscription.State.SUSPENDED:
        return False
    if subscription.state == TenantSubscription.State.EXPIRED:
        return False
    if subscription.state == TenantSubscription.State.TRIAL:
        return not subscription.trial_ends_at or subscription.trial_ends_at > now
    if subscription.state == TenantSubscription.State.GRACE:
        return not subscription.grace_ends_at or subscription.grace_ends_at > now
    return subscription.state == TenantSubscription.State.ACTIVE


def usage_total(tenant, metric, *, now=None):
    now = now or timezone.now()
    records = UsageRecord.all_objects.filter(tenant=tenant, metric=metric)
    if metric in MONTHLY_METRICS:
        records = records.filter(recorded_at__year=now.year, recorded_at__month=now.month)
    return records.aggregate(total=Sum("quantity"))["total"] or 0


def enforce(tenant, code, *, quantity=1, item=None, current_usage=None):
    """Raise when a subscribed tenant cannot consume an entitlement.

    Existing private-install tenants without a subscription remain
    grandfathered for backward compatibility. Every SaaS-onboarded tenant gets
    a subscription and is therefore enforced here.
    """
    subscription = _subscription(tenant)
    if subscription is None:
        return
    now = timezone.now()
    if not _usable(subscription, now):
        raise EntitlementDenied("The tenant subscription is not active.")
    entitlement = TenantEntitlement.all_objects.filter(tenant=tenant, code=code).first()
    if entitlement is None:
        value = subscription.entitlement_snapshot.get(code)
        enabled = value is not False and value is not None
        limit = value if isinstance(value, int) and not isinstance(value, bool) else None
        configuration = {"allow": value} if isinstance(value, list) else {}
    else:
        enabled, limit, configuration = entitlement.enabled, entitlement.limit, entitlement.configuration
    if not enabled:
        raise EntitlementDenied(f"The {code} entitlement is disabled.")
    allowed = configuration.get("allow")
    if item is not None and allowed is not None and item not in allowed:
        raise EntitlementDenied(f"{item!r} is not licensed by the {code} entitlement.")
    consumed = usage_total(tenant, code, now=now) if current_usage is None else current_usage
    if limit is not None and consumed + quantity > limit:
        raise EntitlementDenied(f"The {code} quota is exhausted.")


def record_usage(tenant, metric, quantity, *, source_type="", source_id=None, idempotency_key=""):
    values = {
        "tenant": tenant,
        "metric": metric,
        "quantity": quantity,
        "source_type": source_type,
        "source_id": source_id,
        "idempotency_key": idempotency_key,
    }
    if not idempotency_key:
        return UsageRecord.all_objects.create(**values)
    return UsageRecord.all_objects.get_or_create(
        tenant=tenant,
        idempotency_key=idempotency_key,
        defaults={key: value for key, value in values.items() if key not in {"tenant", "idempotency_key"}},
    )[0]
