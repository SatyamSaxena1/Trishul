import hashlib
import json
import uuid

from django.db import migrations
from django.utils import timezone

MACHINES = (
    ("core", "Engagement", "engagement", "status"),
    ("core", "OrganisationControl", "organisation_control", "status"),
    ("deployment_assurance", "EvaluationRun", "deployment_evaluation", "state"),
)


def import_current_states(apps, schema_editor):
    AuditEvent = apps.get_model("core", "AuditEvent")
    Tenant = apps.get_model("core", "Tenant")
    WorkflowTransition = apps.get_model("workflow", "WorkflowTransition")
    is_postgres = schema_editor.connection.vendor == "postgresql"

    for tenant_id in Tenant.objects.values_list("id", flat=True).iterator():
        if is_postgres:
            with schema_editor.connection.cursor() as cursor:
                cursor.execute("SELECT set_config('trishul.tenant_id', %s, true)", [str(tenant_id)])
        for app_label, model_name, machine, state_field in MACHINES:
            model = apps.get_model(app_label, model_name)
            for entity in model.objects.filter(tenant_id=tenant_id).iterator():
                _import_entity(
                    AuditEvent=AuditEvent,
                    WorkflowTransition=WorkflowTransition,
                    entity=entity,
                    machine=machine,
                    state_field=state_field,
                )


def _import_entity(*, AuditEvent, WorkflowTransition, entity, machine, state_field):
    tenant_id = entity.tenant_id
    occurred_at = timezone.now()
    previous = AuditEvent.objects.filter(tenant_id=tenant_id).order_by("-occurred_at", "-id").first()
    previous_hash = previous.event_hash if previous else ""
    state = getattr(entity, state_field)
    details = {
        "machine_version": 1,
        "from_state": "",
        "to_state": state,
        "entity_version": entity.version,
        "reason_code": "EXISTING_STATE_IMPORTED",
    }
    payload = json.dumps(
        {
            "tenant": str(tenant_id),
            "actor_type": "system",
            "actor_id": "workflow-migration",
            "action": f"workflow.{machine}.migration_imported",
            "resource_type": entity._meta.label_lower,
            "resource_id": str(entity.pk),
            "details": details,
            "occurred_at": occurred_at.isoformat(),
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    audit = AuditEvent.objects.create(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        actor_type="system",
        actor_id="workflow-migration",
        action=f"workflow.{machine}.migration_imported",
        resource_type=entity._meta.label_lower,
        resource_id=entity.pk,
        details=details,
        occurred_at=occurred_at,
        previous_hash=previous_hash,
        event_hash=hashlib.sha256(payload.encode()).hexdigest(),
    )
    WorkflowTransition.objects.create(
        tenant_id=tenant_id,
        machine=machine,
        machine_version=1,
        entity_type=entity._meta.label_lower,
        entity_id=entity.pk,
        event="migration_imported",
        from_state="",
        to_state=state,
        entity_version_before=entity.version,
        entity_version_after=entity.version,
        actor_type="system",
        actor_id="workflow-migration",
        reason_code="EXISTING_STATE_IMPORTED",
        audit_event_id=audit.id,
    )


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0002_tenant_security"),
        ("deployment_assurance", "0004_saas_tenant_security"),
    ]
    operations = [migrations.RunPython(import_current_states, migrations.RunPython.noop)]
