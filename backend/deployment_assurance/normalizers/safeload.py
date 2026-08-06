"""Bounded parsing of untrusted JSON and YAML.

``yaml.safe_load`` already refuses arbitrary object construction, and
``json.loads`` refuses code entirely. What neither refuses is a structurally
hostile document: a billion-laugh alias expansion, a hundred-thousand-deep
nesting, or a multi-gigabyte scalar. The helpers here add those bounds and are
the only sanctioned entry points for parsing an artifact.
"""

import json
from typing import Any, Iterator

import yaml

from ..limits import (
    MAX_ARTIFACT_BYTES,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_YAML_DOCUMENTS,
    ArtifactTooLarge,
    UnsafeArtifact,
)


class BoundedSafeLoader(yaml.SafeLoader):
    """A ``SafeLoader`` that additionally refuses alias expansion.

    Aliases are the mechanism behind exponential-expansion ("billion laughs")
    attacks: the blow-up happens inside the composer, before any size check we
    could apply to the resulting object graph. Refusing aliases outright is the
    only bound that holds, and legitimate deployment manifests very rarely use
    them. This deliberately subclasses the pure-Python loader — the libyaml
    composer is not overridable from Python.
    """

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            raise UnsafeArtifact("YAML aliases are not accepted in deployment artifacts.")
        return super().compose_node(parent, index)


def _check_size(payload: bytes) -> None:
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ArtifactTooLarge(f"Artifact exceeds {MAX_ARTIFACT_BYTES} bytes.")


def _walk(value: Any, depth: int, budget: list[int]) -> None:
    if depth > MAX_DOCUMENT_DEPTH:
        raise UnsafeArtifact("Document nesting exceeds the permitted depth.")
    budget[0] -= 1
    if budget[0] < 0:
        raise UnsafeArtifact(f"Document exceeds {MAX_DOCUMENT_NODES} nodes.")
    if isinstance(value, dict):
        for key, item in value.items():
            _walk(key, depth + 1, budget)
            _walk(item, depth + 1, budget)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk(item, depth + 1, budget)


def _validate(document: Any) -> Any:
    _walk(document, 0, [MAX_DOCUMENT_NODES])
    return document


def load_json(payload: bytes) -> Any:
    """Parse a single JSON document within structural bounds."""
    _check_size(payload)
    try:
        document = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise UnsafeArtifact("Artifact is not valid UTF-8.") from exc
    except RecursionError as exc:
        raise UnsafeArtifact("JSON nesting exceeds the permitted depth.") from exc
    except json.JSONDecodeError as exc:
        raise UnsafeArtifact(f"Artifact is not valid JSON: {exc.msg}") from exc
    return _validate(document)


def load_yaml_documents(payload: bytes) -> Iterator[Any]:
    """Parse a multi-document YAML stream within structural bounds.

    Yields each document in order. YAML is a JSON superset, so a JSON artifact
    submitted with a YAML source type still parses correctly.
    """
    _check_size(payload)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafeArtifact("Artifact is not valid UTF-8.") from exc
    try:
        documents = list(yaml.load_all(text, Loader=BoundedSafeLoader))
    except yaml.YAMLError as exc:
        raise UnsafeArtifact(f"Artifact is not valid YAML: {type(exc).__name__}") from exc
    except RecursionError as exc:
        raise UnsafeArtifact("YAML nesting exceeds the permitted depth.") from exc
    if len(documents) > MAX_YAML_DOCUMENTS:
        raise UnsafeArtifact(f"Artifact contains more than {MAX_YAML_DOCUMENTS} YAML documents.")
    budget = [MAX_DOCUMENT_NODES]
    for document in documents:
        if document is None:
            continue
        _walk(document, 0, budget)
        yield document
