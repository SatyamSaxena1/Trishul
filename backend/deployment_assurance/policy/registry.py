"""The rule registry and pack synchronisation.

Rules exist in two places and the relationship between them is deliberate:

* **In code** — the authoritative definition, shipped and reviewed with the
  release, addressed by a content hash over its full definition.
* **In the database** — a ``PolicyPack`` row per version, used for referential
  integrity, tenant tailoring and historical reproducibility.

``sync_pack`` projects the former into the latter, and refuses to mutate a pack
whose content hash has changed: a modified rule requires a new pack version, so
an evaluation completed last month still resolves to exactly the rules that ran.
"""

import hashlib
from typing import Iterable, Iterator

from ..resources import canonical_json
from .sdk import ResourceRule


class PolicyPackConflict(RuntimeError):
    """A stored pack version does not match the shipped rule definitions."""


class RuleRegistry:
    """An immutable, ordered collection of registered rules."""

    def __init__(self, key: str, version: str, title: str, description: str, rules: Iterable[ResourceRule]):
        self.key = key
        self.version = version
        self.title = title
        self.description = description
        self._rules: dict[str, ResourceRule] = {}
        for rule in rules:
            if not rule.rule_id:
                raise ValueError(f"{type(rule).__name__} does not declare a rule_id.")
            if rule.rule_id in self._rules:
                raise ValueError(f"Duplicate rule_id {rule.rule_id!r} in pack {key!r}.")
            unknown = set(rule.resource_types) - _known_resource_types()
            if unknown:
                raise ValueError(f"Rule {rule.rule_id} declares unknown resource types: {sorted(unknown)}.")
            self._rules[rule.rule_id] = rule

    def __iter__(self) -> Iterator[ResourceRule]:
        """Iterate in ``rule_id`` order so evaluation output is deterministic."""
        return iter(sorted(self._rules.values(), key=lambda rule: rule.rule_id))

    def __len__(self) -> int:
        return len(self._rules)

    def get(self, rule_id: str) -> ResourceRule | None:
        return self._rules.get(rule_id)

    @property
    def covered_resource_types(self) -> frozenset[str]:
        return frozenset(item for rule in self._rules.values() for item in rule.resource_types)

    def content_hash(self) -> str:
        payload = canonical_json(
            {
                "key": self.key,
                "version": self.version,
                "rules": [rule.definition() for rule in self],
            }
        )
        return hashlib.sha256(payload).hexdigest()


def _known_resource_types() -> frozenset[str]:
    from ..resources import ResourceType

    return ResourceType.ALL


def _build_default_registry() -> RuleRegistry:
    from .packs import baseline

    return RuleRegistry(
        key=baseline.PACK_KEY,
        version=baseline.PACK_VERSION,
        title=baseline.PACK_TITLE,
        description=baseline.PACK_DESCRIPTION,
        rules=baseline.RULES,
    )


#: The pack shipped with this release.
REGISTRY = _build_default_registry()


def sync_pack(tenant, *, registry: RuleRegistry | None = None, approve: bool = True):
    """Create or verify the database projection of a registry for one tenant.

    Idempotent. Returns the ``PolicyPack``. Raises :class:`PolicyPackConflict`
    if a pack with the same key and version exists under a different content
    hash, which means rule code changed without a version bump.
    """
    from django.utils import timezone

    from ..models import ControlMapping, PolicyPack, PolicyRule
    from . import ENGINE_VERSION

    registry = registry or REGISTRY
    content_hash = registry.content_hash()

    existing = PolicyPack.all_objects.filter(tenant=tenant, key=registry.key, pack_version=registry.version).first()
    if existing:
        if existing.content_hash != content_hash:
            raise PolicyPackConflict(
                f"Pack {registry.key}@{registry.version} is already stored with a different content hash. "
                "Publish a new pack version instead of modifying a released one."
            )
        for rule in registry:
            stored = existing.rules.filter(stable_key=rule.rule_id).first()
            if stored and stored.unified_control_id is None:
                stored.unified_control = _sync_uco(tenant, rule, approve=approve)
                stored.save(update_fields=["unified_control", "updated_at"])
        return existing

    pack = PolicyPack.all_objects.create(
        tenant=tenant,
        key=registry.key,
        pack_version=registry.version,
        title=registry.title,
        description=registry.description,
        content_hash=content_hash,
        engine_version=ENGINE_VERSION,
        approved_at=timezone.now() if approve else None,
    )
    for rule in registry:
        unified_control = _sync_uco(tenant, rule, approve=approve)
        stored = PolicyRule.all_objects.create(
            tenant=tenant,
            policy_pack=pack,
            unified_control=unified_control,
            stable_key=rule.rule_id,
            rule_version=rule.rule_version,
            title=rule.title,
            description=rule.description,
            category=rule.category,
            severity=rule.severity,
            entrypoint=rule.entrypoint,
            resource_types=sorted(rule.resource_types),
            parameters=dict(rule.default_parameters),
            remediation_guidance=rule.remediation,
            automation_class=rule.automation_class,
            blocking=rule.blocking,
            content_hash=rule.content_hash(),
        )
        for framework, framework_version, control_id in rule.mappings:
            ControlMapping.all_objects.create(
                tenant=tenant,
                policy_rule=stored,
                framework=framework,
                framework_version=framework_version,
                control_id=control_id,
                note="Control traceability: this rule contributes evidence toward the control.",
            )
    return pack


def _sync_uco(tenant, rule, *, approve):
    """Project a technical rule into the tenant's versioned UCF content."""
    from django.utils import timezone

    from core.models import EvidenceRequirement, UnifiedControlObjective

    unified_control, _ = UnifiedControlObjective.all_objects.get_or_create(
        tenant=tenant,
        code=f"UCO-{rule.rule_id.removeprefix('DA-')}",
        objective_version=rule.rule_version,
        defaults={
            "domain": rule.category,
            "objective": rule.description,
            "control_type": UnifiedControlObjective.ControlType.PREVENTIVE,
            "nature": UnifiedControlObjective.Nature.TECHNICAL,
            "approved_at": timezone.now() if approve else None,
        },
    )
    EvidenceRequirement.all_objects.get_or_create(
        tenant=tenant,
        unified_control=unified_control,
        artefact_type="system_generated_deployment_result",
        defaults={
            "required_attributes": ["rule_id", "rule_version", "resource_id", "outcome", "result_hash"],
            "acceptance_criteria": {"outcome": "pass"},
        },
    )
    return unified_control
