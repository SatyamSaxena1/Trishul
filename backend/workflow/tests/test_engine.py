from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.test import APIClient

from core.models import Engagement, Membership, Tenant
from core.tenancy import tenant_context
from workflow.engine import InvalidTransition, StaleTransition, transition
from workflow.machines import ENGAGEMENT
from workflow.models import WorkflowTransition

pytestmark = pytest.mark.django_db


def engagement():
    firm = Tenant.objects.create(slug="firm-workflow", name="Firm", tenant_type=Tenant.Type.AUDIT_FIRM)
    auditee = Tenant.objects.create(slug="auditee-workflow", name="Auditee", tenant_type=Tenant.Type.AUDITEE)
    user = get_user_model().objects.create(username="workflow-manager")
    with tenant_context(firm.id):
        Membership.objects.create(tenant=firm, user=user, role=Membership.Role.AUDIT_MANAGER)
        item = Engagement.objects.create(
            tenant=firm,
            auditee_tenant=auditee,
            name="FY27 audit",
            reference="WF-1",
            framework_scope=["ISO/IEC 27001:2022"],
            starts_on=timezone.localdate(),
            ends_on=timezone.localdate() + timedelta(days=30),
            created_by=user,
        )
    return firm, user, item


def test_transition_is_atomic_audited_immutable_and_idempotent():
    firm, user, item = engagement()
    with tenant_context(firm.id):
        result = transition(
            model=Engagement,
            entity_id=item.id,
            machine=ENGAGEMENT,
            event="activate",
            tenant=firm,
            actor_type="user",
            actor_id=str(user.id),
            actor_tenant=firm,
            expected_version=item.version,
            idempotency_key="activate-1",
        )
        replay = transition(
            model=Engagement,
            entity_id=item.id,
            machine=ENGAGEMENT,
            event="activate",
            tenant=firm,
            actor_type="user",
            actor_id=str(user.id),
            expected_version=item.version,
            idempotency_key="activate-1",
        )

        assert result.entity.status == Engagement.Status.ACTIVE
        assert result.entity.version == item.version + 1
        assert replay.replayed is True
        assert WorkflowTransition.objects.count() == 1
        assert result.transition.audit_event.action == "workflow.engagement.activate"
        result.transition.reason = "changed"
        with pytest.raises(ValidationError):
            result.transition.save()


def test_invalid_and_stale_transitions_fail_closed():
    firm, user, item = engagement()
    with tenant_context(firm.id):
        with pytest.raises(InvalidTransition):
            transition(
                model=Engagement,
                entity_id=item.id,
                machine=ENGAGEMENT,
                event="close",
                tenant=firm,
                actor_type="user",
                actor_id=str(user.id),
                expected_version=item.version,
            )
        item.version += 1
        item.save(update_fields=["version", "updated_at"])
        with pytest.raises(StaleTransition):
            transition(
                model=Engagement,
                entity_id=item.id,
                machine=ENGAGEMENT,
                event="activate",
                tenant=firm,
                actor_type="user",
                actor_id=str(user.id),
                expected_version=item.version - 1,
            )


def test_engagement_transition_api_requires_version_and_replays_idempotently():
    firm, user, item = engagement()
    client = APIClient()
    client.force_authenticate(user)
    url = f"/api/v1/engagements/{item.id}/transition/"

    assert client.post(url, {"event": "activate"}, format="json").status_code == 428
    assert client.post(url, {"event": "activate"}, format="json", HTTP_IF_MATCH="99").status_code == 412
    activated = client.post(
        url,
        {"event": "activate"},
        format="json",
        HTTP_IF_MATCH=str(item.version),
        HTTP_IDEMPOTENCY_KEY="activate-api-1",
    )
    assert activated.status_code == 200
    assert activated.json()["status"] == Engagement.Status.ACTIVE
    replay = client.post(
        url,
        {"event": "activate"},
        format="json",
        HTTP_IF_MATCH=str(item.version),
        HTTP_IDEMPOTENCY_KEY="activate-api-1",
    )
    assert replay.status_code == 200
