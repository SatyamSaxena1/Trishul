import json
from collections import Counter
from pathlib import Path

OUTCOMES = {"accepted", "false_positive", "duplicate", "needs_context"}


def summarize_reviews(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = []
    for rule_id in sorted({review["rule_id"] for review in data["reviews"]}):
        reviews = [review for review in data["reviews"] if review["rule_id"] == rule_id]
        counts = Counter(review["outcome"] for review in reviews)
        unknown = set(counts) - OUTCOMES
        if unknown:
            raise ValueError(f"Unknown review outcomes: {sorted(unknown)}")
        reviewed = len(reviews)
        accepted = counts["accepted"]
        rows.append(
            {
                "rule_id": rule_id,
                "reviewed": reviewed,
                "accepted": accepted,
                "false_positives": counts["false_positive"],
                "duplicates": counts["duplicate"],
                "needs_context": counts["needs_context"],
                "usefulness_percentage": round(accepted * 100 / reviewed, 1) if reviewed else 0.0,
            }
        )
    return {"corpus_version": data["corpus_version"], "review_version": data["review_version"], "rules": rows}


def markdown_report(summary):
    lines = [
        "# Per-rule quality report",
        "",
        f"Corpus version: `{summary['corpus_version']}`. Pilot review version: `{summary['review_version']}`.",
        "Usefulness is `accepted / reviewed × 100`; every terminal outcome is included in reviewed count.",
        "",
        "| Rule | Reviewed | Accepted | False positives | Duplicates | Needs context | Usefulness |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary["rules"]:
        lines.append(
            f"| {row['rule_id']} | {row['reviewed']} | {row['accepted']} | "
            f"{row['false_positives']} | {row['duplicates']} | {row['needs_context']} | "
            f"{row['usefulness_percentage']:.1f}% |"
        )
    totals = {key: sum(row[key] for row in summary["rules"]) for key in (
        "reviewed", "accepted", "false_positives", "duplicates", "needs_context"
    )}
    usefulness = totals["accepted"] * 100 / totals["reviewed"] if totals["reviewed"] else 0
    lines.append(
        f"| **Overall** | **{totals['reviewed']}** | **{totals['accepted']}** | "
        f"**{totals['false_positives']}** | **{totals['duplicates']}** | "
        f"**{totals['needs_context']}** | **{usefulness:.1f}%** |"
    )
    return "\n".join(lines) + "\n"
