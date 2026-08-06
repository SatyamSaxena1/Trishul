"""Deterministic policy evaluation.

The MVP engine is native Python by deliberate choice. A registered Python rule
runs in the same isolated process as the normalizer, needs no extra runtime, and
is trivially unit-testable — which matters more at this stage than declarative
expressiveness. The SDK boundary in ``sdk.py`` is intentionally narrow so that
an OPA/Rego adapter can be added later behind the same input and result
contracts without touching rule consumers.

Rules are *registered code*, never uploaded code. The API accepts parameters and
rule selection; it never accepts an entrypoint that is not already in the
registry shipped with the release.
"""

from .registry import REGISTRY, RuleRegistry
from .sdk import ResourceRule, RuleContext, RuleResult

ENGINE_VERSION = "1.0.0"

__all__ = ["ENGINE_VERSION", "REGISTRY", "ResourceRule", "RuleContext", "RuleRegistry", "RuleResult"]
