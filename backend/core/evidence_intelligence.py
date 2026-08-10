import re
from datetime import date
from decimal import ROUND_HALF_UP, Decimal

EXTRACTABLE_TYPES = {"text/plain", "text/markdown", "text/csv"}
EXTRACTOR_VERSION = "native-text-1.0"
QUALITY_VERSION = "evidence-quality-1.0"
DEFAULT_WEIGHTS = {
    "completeness": 25,
    "freshness": 20,
    "authenticity": 20,
    "scope_coverage": 15,
    "legibility": 10,
    "corroboration": 10,
}
DATE_FIELDS = ("issue_date", "effective_date", "review_date", "next_review_date", "expiry_date")


def _label(text, label):
    match = re.search(rf"(?im)^\s*{label}\s*:\s*(.+?)\s*$", text)
    return (match.group(1).strip(), text.count("\n", 0, match.start()) + 1) if match else None


def analyse(file_obj, *, title, media_type, evidence_date, profile=None, today=None):
    profile = profile or {}
    extractable = media_type.split(";", 1)[0].lower() in EXTRACTABLE_TYPES
    file_obj.seek(0)
    raw = file_obj.read(1_000_001) if extractable else b""
    file_obj.seek(0)
    truncated = len(raw) > 1_000_000
    text = raw[:1_000_000].decode("utf-8", errors="replace")
    attributes = {
        "document_title": title,
        "document_type": media_type.split(";", 1)[0].lower(),
        "evidence_date": evidence_date.isoformat(),
    }
    references = {}
    if text:
        for field in DATE_FIELDS:
            if found := _label(text, field.replace("_", r"[ _-]+")):
                value, line = found
                try:
                    attributes[field] = date.fromisoformat(value).isoformat()
                    references[field] = {"line": line}
                except ValueError:
                    pass
        if found := _label(text, r"approved[ _-]+by"):
            value, line = found
            attributes["approver_name"] = value
            references["approver_name"] = {"line": line}
        attributes["signature_present"] = bool(re.search(r"(?i)\b(signature|signed by|e-signed)\b", text))
        if found := _label(text, "scope"):
            value, line = found
            attributes["scope_statement"] = value
            attributes["systems_covered"] = [item.strip() for item in value.split(",") if item.strip()]
            references["scope_statement"] = {"line": line}
        period = re.search(r"(?im)^\s*period(?: covered)?\s*:\s*(\d{4}-\d{2}-\d{2})\s+to\s+(\d{4}-\d{2}-\d{2})", text)
        if period:
            try:
                start, end = (date.fromisoformat(value).isoformat() for value in period.groups())
                attributes["period_covered_from"], attributes["period_covered_to"] = start, end
                references["period_covered"] = {"line": text.count("\n", 0, period.start()) + 1}
            except ValueError:
                pass
        parameters = {
            key.lower().replace(" ", "_"): int(value)
            for key, value in re.findall(
                r"(?im)^\s*(password minimum length|retention days|rpo minutes|rto minutes)\s*:\s*(\d+)\s*$",
                text,
            )
        }
        if parameters:
            attributes["control_parameters"] = parameters

    components = _quality(attributes, evidence_date=evidence_date, legible=bool(text) and not truncated, today=today)
    weights = {**DEFAULT_WEIGHTS, **profile.get("weights", {})}
    weight_total = sum(max(0, int(value)) for value in weights.values()) or 1
    total = sum(Decimal(str(components[name])) * max(0, int(weight)) for name, weight in weights.items())
    total = (total / weight_total).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    threshold = Decimal(str(profile.get("threshold", "2.5")))
    weak = [name.replace("_", " ") for name, value in components.items() if value < 5]
    return {
        "attributes": attributes,
        "provenance": {
            "extractor_version": EXTRACTOR_VERSION,
            "source": "uploaded_bytes",
            "truncated": truncated,
            "unsupported_media_type": not extractable,
            "references": references,
        },
        "confidence": Decimal("1.00") if extractable and not truncated else Decimal("0.00"),
        "quality_score": total,
        "quality_breakdown": components,
        "quality_reasons": [f"Needs improvement: {name}." for name in weak],
        "quality_suggestions": [f"Provide verifiable {name}." for name in weak],
        "quality_threshold": threshold,
        "quality_passed": total >= threshold,
        "quality_profile_version": profile.get("version", QUALITY_VERSION),
    }


def _quality(attributes, *, evidence_date, legible, today=None):
    today = today or date.today()
    complete = ("effective_date", "review_date", "approver_name", "scope_statement")
    completeness = Decimal("5") * sum(bool(attributes.get(name)) for name in complete) / len(complete)
    age = (today - evidence_date).days
    freshness = 5 if age <= 365 else 2.5 if age <= 730 else 0
    authenticity = 2.5 * bool(attributes.get("approver_name")) + 2.5 * bool(attributes.get("signature_present"))
    return {
        "completeness": float(completeness),
        "freshness": freshness,
        "authenticity": authenticity,
        "scope_coverage": 5 if attributes.get("scope_statement") else 0,
        "legibility": 5 if legible else 0,
        "corroboration": 0,
    }
