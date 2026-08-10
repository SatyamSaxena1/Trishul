"""Hard bounds applied to untrusted deployment artifacts.

Every deployment artifact submitted to the platform is untrusted input. These
limits are enforced before and during normalization so that a hostile plan,
manifest or inventory cannot exhaust worker memory, CPU or storage. They are
deliberately module-level constants rather than settings: relaxing a bound is a
code change that passes through review.
"""

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
MAX_NORMALIZED_BYTES = 64 * 1024 * 1024
MAX_RESULT_MANIFEST_BYTES = 32 * 1024 * 1024

MAX_YAML_DOCUMENTS = 2_000
MAX_DOCUMENT_DEPTH = 64
MAX_DOCUMENT_NODES = 400_000

MAX_RESOURCES = 20_000
MAX_RESULTS = 100_000
MAX_RESULTS_PER_RULE = 20_000

MAX_ATTRIBUTE_BYTES = 8_000
MAX_RATIONALE_CHARS = 2_000
MAX_STRING_CHARS = 4_000
MAX_COLLECTION_ITEMS = 512


class ArtifactTooLarge(ValueError):
    """The submitted artifact exceeds a hard ingestion bound."""


class UnsafeArtifact(ValueError):
    """The submitted artifact is malformed or violates a structural bound."""
