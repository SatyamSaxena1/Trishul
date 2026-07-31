from prometheus_client import Counter

DETERMINISTIC_ANALYSIS_FAILURES = Counter(
    "trishul_deterministic_analysis_failures_total",
    "Deterministic scan analysis failures.",
)
OPTIONAL_AI_FAILURES = Counter(
    "trishul_optional_ai_failures_total",
    "Optional AI enrichment failures.",
    ("reason",),
)
