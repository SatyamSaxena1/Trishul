"""The rule authoring contract.

A rule is a small, pure object. It receives a ``RuleContext`` (target facts and
resolved parameters) and one ``Resource``, and returns zero or more
``RuleResult`` values. It may not perform I/O, read settings, touch the ORM or
consult wall-clock time except through the context.

That restriction is what makes a decision reproducible: given the same snapshot,
the same pack and the same engine version, the result content is byte-identical.
Anything that could vary between runs has to arrive through the context, where
it is recorded as an evaluation input.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..limits import MAX_RATIONALE_CHARS, MAX_RESULTS_PER_RULE
from ..resources import Resource, canonical_json

PASS = "pass"  # noqa: S105 - a rule outcome, not a credential
FAIL = "fail"
WARNING = "warning"
NOT_APPLICABLE = "not_applicable"
MANUAL_REVIEW = "manual_review"

VALID_OUTCOMES = frozenset({PASS, FAIL, WARNING, NOT_APPLICABLE, MANUAL_REVIEW})


class RuleContractError(RuntimeError):
    """A rule returned output that violates the SDK contract."""


@dataclass(frozen=True)
class TargetFacts:
    """The deployment context a rule is allowed to consider.

    A rule may vary its verdict by environment or exposure — a warning in
    development can legitimately be a block in production — but only through
    these declared facts, never by reading the database.
    """

    environment: str
    provider: str
    criticality: int
    data_sensitivity: int
    internet_exposed: bool
    is_production: bool


@dataclass(frozen=True)
class RuleContext:
    target: TargetFacts
    parameters: Mapping[str, Any] = field(default_factory=dict)
    policy_version: str = ""

    def parameter(self, key: str, default: Any = None) -> Any:
        return self.parameters.get(key, default)


@dataclass(frozen=True)
class RuleResult:
    """One outcome for one resource.

    ``reason_code`` is a stable machine identifier and participates in the
    result fingerprint. Changing it retires the old finding and opens a new one,
    so treat it as part of the rule's public contract.
    """

    outcome: str
    reason_code: str
    rationale: str
    observed: Mapping[str, Any] = field(default_factory=dict)
    expected: Mapping[str, Any] = field(default_factory=dict)
    severity: int | None = None
    confidence: int = 4

    def __post_init__(self):
        if self.outcome not in VALID_OUTCOMES:
            raise RuleContractError(f"Invalid outcome {self.outcome!r}.")
        if not self.reason_code or len(self.reason_code) > 80:
            raise RuleContractError("reason_code must be a non-empty identifier of at most 80 characters.")
        if not 0 <= self.confidence <= 5:
            raise RuleContractError("confidence must be between 0 and 5.")
        if self.severity is not None and not 0 <= self.severity <= 5:
            raise RuleContractError("severity must be between 0 and 5.")


class ResourceRule:
    """Base class for a rule that examines one resource at a time.

    Subclasses set the class attributes and implement :meth:`check`. The base
    class handles applicability filtering so a rule body never has to defend
    against being handed a resource type it does not understand.
    """

    rule_id: str = ""
    rule_version: str = "1.0.0"
    title: str = ""
    description: str = ""
    category: str = "configuration"
    severity: int = 3
    resource_types: tuple[str, ...] = ()
    remediation: str = ""
    blocking: bool = False
    automation_class: str = "guidance"
    default_parameters: Mapping[str, Any] = {}
    # Framework traceability. Contributing evidence toward a control, not proof
    # of compliance with it.
    mappings: tuple[tuple[str, str, str], ...] = ()

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:  # pragma: no cover - abstract
        raise NotImplementedError

    def evaluate(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if resource.resource_type not in self.resource_types:
            return ()
        results = self.check(context, resource) or ()
        if len(results) > MAX_RESULTS_PER_RULE:
            raise RuleContractError(f"Rule {self.rule_id} returned more than {MAX_RESULTS_PER_RULE} results.")
        return [self._bound(result) for result in results]

    def _bound(self, result: RuleResult) -> RuleResult:
        if not isinstance(result, RuleResult):
            raise RuleContractError(f"Rule {self.rule_id} returned {type(result).__name__}, expected RuleResult.")
        if len(result.rationale) <= MAX_RATIONALE_CHARS:
            return result
        return RuleResult(
            outcome=result.outcome,
            reason_code=result.reason_code,
            rationale=result.rationale[:MAX_RATIONALE_CHARS] + "…",
            observed=result.observed,
            expected=result.expected,
            severity=result.severity,
            confidence=result.confidence,
        )

    def resolved_parameters(self, overrides: Mapping[str, Any] | None = None) -> dict:
        return {**dict(self.default_parameters), **dict(overrides or {})}

    def definition(self) -> dict:
        """The canonical rule definition used for the pack content hash."""
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "resource_types": sorted(self.resource_types),
            "remediation": self.remediation,
            "blocking": self.blocking,
            "automation_class": self.automation_class,
            "default_parameters": dict(self.default_parameters),
            "mappings": [list(item) for item in self.mappings],
            "entrypoint": self.entrypoint,
        }

    @property
    def entrypoint(self) -> str:
        return f"{type(self).__module__}:{type(self).__qualname__}"

    def content_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.definition())).hexdigest()


def result_fingerprint(
    *, rule_id: str, rule_version: str, resource_type: str, resource_id: str, reason_code: str
) -> str:
    """Stable identity for a finding across evaluation runs.

    Includes the rule version on purpose: a rule whose logic changed produces a
    different fingerprint, which correctly invalidates any waiver written
    against the previous version.
    """
    payload = canonical_json(
        {
            "rule_id": rule_id,
            "rule_version": rule_version,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "reason_code": reason_code,
        }
    )
    return hashlib.sha256(payload).hexdigest()
