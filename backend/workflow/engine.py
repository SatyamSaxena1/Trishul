from dataclasses import dataclass
from typing import Callable

from django.db import transaction

from core.models import AuditEvent, Tenant

from .models import WorkflowTransition


class InvalidTransition(ValueError):
    pass


class StaleTransition(ValueError):
    pass


@dataclass(frozen=True)
class TransitionSpec:
    event: str
    from_states: frozenset[str]
    to_state: str


@dataclass(frozen=True)
class MachineSpec:
    name: str
    version: int
    state_field: str
    transitions: tuple[TransitionSpec, ...]

    def resolve(self, state: str, event: str) -> TransitionSpec:
        for candidate in self.transitions:
            if candidate.event == event and state in candidate.from_states:
                return candidate
        raise InvalidTransition(f"{event!r} is not allowed from {state!r}.")

    def available_events(self, state: str) -> list[str]:
        return sorted(item.event for item in self.transitions if state in item.from_states)


@dataclass(frozen=True)
class TransitionResult:
    entity: object
    transition: WorkflowTransition
    replayed: bool = False


def transition(
    *,
    model,
    entity_id,
    machine: MachineSpec,
    event: str,
    tenant: Tenant,
    actor_type: str,
    actor_id: str,
    expected_version: int,
    actor_tenant: Tenant | None = None,
    engagement_id=None,
    reason: str = "",
    reason_code: str = "",
    idempotency_key: str = "",
    metadata: dict | None = None,
    mutate: Callable[[object], tuple[str, ...] | list[str] | None] | None = None,
) -> TransitionResult:
    """Lock, validate, mutate, audit and record one transition atomically."""
    if expected_version is None:
        raise StaleTransition("The current entity version is required.")
    if len(reason) > 4000 or len(reason_code) > 80 or len(idempotency_key) > 200:
        raise ValueError("Transition metadata exceeds its allowed size.")
    metadata = dict(metadata or {})

    with transaction.atomic():
        if idempotency_key:
            existing = WorkflowTransition.all_objects.filter(
                tenant=tenant,
                machine=machine.name,
                entity_id=entity_id,
                idempotency_key=idempotency_key,
            ).first()
            if existing:
                entity = model.all_objects.get(tenant=tenant, pk=entity_id)
                return TransitionResult(entity=entity, transition=existing, replayed=True)

        entity = model.all_objects.select_for_update().get(tenant=tenant, pk=entity_id)
        if entity.version != expected_version:
            raise StaleTransition(f"Expected version {expected_version}; current version is {entity.version}.")
        from_state = getattr(entity, machine.state_field)
        resolved = machine.resolve(from_state, event)
        setattr(entity, machine.state_field, resolved.to_state)
        extra_fields = tuple(mutate(entity) or ()) if mutate else ()
        entity.version += 1
        entity.save(update_fields=[machine.state_field, "version", "updated_at", *extra_fields])

        entity_type = entity._meta.label_lower
        audit = AuditEvent.append(
            tenant=tenant,
            actor_type=actor_type,
            actor_id=str(actor_id),
            action=f"workflow.{machine.name}.{event}",
            resource_type=entity_type,
            resource_id=entity.pk,
            details={
                "machine_version": machine.version,
                "from_state": from_state,
                "to_state": resolved.to_state,
                "entity_version": entity.version,
                **({"reason_code": reason_code} if reason_code else {}),
            },
        )
        record = WorkflowTransition.all_objects.create(
            tenant=tenant,
            machine=machine.name,
            machine_version=machine.version,
            entity_type=entity_type,
            entity_id=entity.pk,
            event=event,
            from_state=from_state,
            to_state=resolved.to_state,
            entity_version_before=expected_version,
            entity_version_after=entity.version,
            actor_type=actor_type,
            actor_id=str(actor_id),
            actor_tenant=actor_tenant,
            engagement_id=engagement_id,
            reason=reason,
            reason_code=reason_code,
            idempotency_key=idempotency_key,
            metadata=metadata,
            audit_event=audit,
        )
        return TransitionResult(entity=entity, transition=record)
