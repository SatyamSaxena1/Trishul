"""Central authorization-decision audit hook: allow/deny recording, append-only
storage, and audit-chain hash linkage on the pre-existing AuditEvent ledger."""

import hashlib
import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import AuditEvent, CrossTenantAccessEvent, Membership, ServiceAccount, Tenant
from core.tenancy import tenant_context

pytestmark = pytest.mark.django_db


def member(tenant, role, username):
    user = get_user_model().objects.create(username=username)
    Membership.all_objects.create(tenant=tenant, user=user, role=role)
    return user


def client_for(user, tenant):
    client = APIClient()
    client.force_authenticate(user)
    client.credentials(HTTP_X_TRISHUL_TENANT=str(tenant.id))
    return client


def test_allowed_and_denied_permission_checks_are_both_centrally_recorded():
    tenant = Tenant.objects.create(slug="audit-hook", name="Audit hook")
    admin = member(tenant, Membership.Role.ORG_ADMIN, "audit-admin")  # has application.read
    owner = member(tenant, Membership.Role.CONTROL_OWNER, "audit-owner")  # lacks application.read
    admin_client = client_for(admin, tenant)
    owner_client = client_for(owner, tenant)

    allowed = admin_client.get("/api/v1/applications/")
    assert allowed.status_code == 200
    denied = owner_client.get("/api/v1/applications/")
    assert denied.status_code == 403

    allow_event = CrossTenantAccessEvent.all_objects.filter(
        tenant=tenant, subject_id=str(admin.id), action="application.read", decision="allow"
    ).first()
    deny_event = CrossTenantAccessEvent.all_objects.filter(
        tenant=tenant, subject_id=str(owner.id), action="application.read", decision="deny"
    ).first()
    assert allow_event is not None
    assert deny_event is not None
    assert deny_event.reason == "permission_not_granted"


def test_authorization_decision_events_are_append_only():
    tenant = Tenant.objects.create(slug="audit-immutable", name="Audit immutable")
    admin = member(tenant, Membership.Role.ORG_ADMIN, "immutable-admin")
    client_for(admin, tenant).get("/api/v1/applications/")
    event = CrossTenantAccessEvent.all_objects.filter(tenant=tenant).first()
    assert event is not None

    with pytest.raises(ValidationError):
        event.reason = "tampered"
        event.save()
    with pytest.raises(ValidationError):
        event.delete()


def test_authorization_decision_events_carry_no_sensitive_payload():
    tenant = Tenant.objects.create(slug="audit-shape", name="Audit shape")
    admin = member(tenant, Membership.Role.ORG_ADMIN, "shape-admin")
    client_for(admin, tenant).get("/api/v1/applications/")
    event = CrossTenantAccessEvent.all_objects.filter(tenant=tenant).first()
    assert event is not None
    field_names = {field.name for field in CrossTenantAccessEvent._meta.get_fields()}
    # The schema itself has nowhere to put evidence content, secrets or tokens --
    # only identifiers, a short reason string and decision metadata.
    assert field_names == {
        "id",
        "created_at",
        "updated_at",
        "version",
        "tenant",
        "target_tenant",
        "engagement",
        "application_id",
        "subject_id",
        "object_type",
        "object_id",
        "action",
        "decision",
        "reason",
        "correlation_id",
        "occurred_at",
    }


def test_audit_event_chain_links_and_detects_reordering():
    tenant = Tenant.objects.create(slug="audit-chain", name="Audit chain")
    with tenant_context(tenant.id):
        first = AuditEvent.append(
            tenant=tenant,
            actor_type="user",
            actor_id="u1",
            action="a",
            resource_type="t",
            resource_id="1",
            details={"step": "first"},
        )
        second = AuditEvent.append(
            tenant=tenant,
            actor_type="user",
            actor_id="u1",
            action="b",
            resource_type="t",
            resource_id="1",
            details={"step": "second"},
        )
    assert first.previous_hash == ""
    assert second.previous_hash == first.event_hash
    assert second.event_hash != first.event_hash

    # The hash is a function of the row's own content, chained to its predecessor --
    # recomputing it from the stored fields must reproduce event_hash exactly, which
    # is what a tamper check would rely on.
    payload = json.dumps(
        {
            "tenant": str(tenant.id),
            "actor_type": second.actor_type,
            "actor_id": second.actor_id,
            "action": second.action,
            "resource_type": second.resource_type,
            "resource_id": str(second.resource_id),
            "details": second.details,
            "occurred_at": second.occurred_at.isoformat(),
            "previous_hash": second.previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assert hashlib.sha256(payload.encode()).hexdigest() == second.event_hash

    with pytest.raises(ValidationError):
        first.delete()
    with pytest.raises(ValidationError):
        first.action = "tampered"
        first.save()


def test_service_account_authorization_decisions_are_also_recorded():
    """A ServicePrincipal caller (not a Membership) must also produce an audit row."""
    tenant = Tenant.objects.create(slug="audit-service", name="Audit service")
    account, token = ServiceAccount.issue(
        tenant=tenant,
        name="svc",
        scopes=["application.read"],
        expires_at=timezone.now() + timedelta(hours=1),
    )
    client = APIClient()
    response = client.get("/api/v1/applications/", HTTP_AUTHORIZATION=f"Bearer {token}")
    assert response.status_code == 200
    event = CrossTenantAccessEvent.all_objects.filter(
        tenant=tenant, subject_id=str(account.id), decision="allow"
    ).first()
    assert event is not None
