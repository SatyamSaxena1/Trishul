from django.core.exceptions import ValidationError
from django.db import models

from core.models import AuditEvent, Tenant, TenantScopedModel


class WorkflowTransition(TenantScopedModel):
    """Immutable history for a domain entity whose current state stays on that entity."""

    machine = models.CharField(max_length=80)
    machine_version = models.PositiveSmallIntegerField()
    entity_type = models.CharField(max_length=100)
    entity_id = models.UUIDField()
    event = models.CharField(max_length=80)
    from_state = models.CharField(max_length=40, blank=True)
    to_state = models.CharField(max_length=40)
    entity_version_before = models.PositiveIntegerField()
    entity_version_after = models.PositiveIntegerField()
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    actor_tenant = models.ForeignKey(
        Tenant, on_delete=models.PROTECT, null=True, blank=True, related_name="workflow_actions"
    )
    engagement_id = models.UUIDField(null=True, blank=True)
    reason = models.TextField(blank=True, max_length=4000)
    reason_code = models.CharField(max_length=80, blank=True)
    idempotency_key = models.CharField(max_length=200, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    audit_event = models.OneToOneField(AuditEvent, on_delete=models.PROTECT, related_name="workflow_transition")

    class Meta:
        ordering = ["created_at", "id"]
        indexes = [models.Index(fields=["tenant", "machine", "entity_id", "created_at"], name="workflow_timeline_idx")]
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "machine", "entity_id", "idempotency_key"],
                condition=models.Q(idempotency_key__gt=""),
                name="workflow_idempotency_uniq",
            )
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).all_objects.filter(pk=self.pk).exists():
            raise ValidationError("Workflow transitions are immutable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Workflow transitions are immutable.")
