"""Standalone normalizer entry point.

Normalization parses untrusted artifacts inside the same disposable,
network-less analyzer job used for code analysis. This pure ``argv`` entry
point needs no database, settings, or credentials.

Usage::

    python -m deployment_assurance.normalizers.cli SOURCE_TYPE INPUT OUTPUT [PROVIDER]

Exit codes: ``0`` success, ``2`` rejected artifact, ``1`` unexpected failure.
"""

import sys
from pathlib import Path

from ..limits import ArtifactTooLarge, UnsafeArtifact
from ..resources import canonical_json


def main(argv: list[str]) -> int:
    if not 4 <= len(argv) <= 5:
        sys.stderr.write("usage: cli SOURCE_TYPE INPUT OUTPUT [PROVIDER]\n")
        return 1
    source_type, input_path, output_path = argv[1], Path(argv[2]), Path(argv[3])
    provider = argv[4] if len(argv) == 5 else "generic"

    # Imported here so that argument errors do not require Django app loading.
    from . import normalize

    try:
        document = normalize(source_type=source_type, payload=input_path.read_bytes(), provider=provider)
    except (UnsafeArtifact, ArtifactTooLarge) as exc:
        # Stable, non-secret reason. Artifact content is never echoed.
        sys.stderr.write(f"rejected: {type(exc).__name__}: {exc}\n")
        return 2
    output_path.write_bytes(canonical_json(document))
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main(sys.argv))
