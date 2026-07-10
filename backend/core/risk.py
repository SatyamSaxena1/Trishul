from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

FORMULA_VERSION = "1.0"
REQUIRED_INPUTS = {
    "exploitability",
    "reachability",
    "exposure",
    "attack_path",
    "threat_relevance",
    "confidence",
    "business_impact",
    "data_sensitivity",
    "regulatory_impact",
    "asset_criticality",
    "blast_radius",
    "control_effectiveness",
    "age_days",
}


@dataclass(frozen=True)
class Score:
    inherent: Decimal
    residual: Decimal
    priority: Decimal


def calculate(inputs: dict) -> Score:
    missing = REQUIRED_INPUTS - inputs.keys()
    if missing:
        raise ValueError(f"Missing risk inputs: {', '.join(sorted(missing))}")
    values = {name: Decimal(str(inputs[name])) for name in REQUIRED_INPUTS}
    for name, value in values.items():
        upper = Decimal("36500") if name == "age_days" else Decimal("5")
        if value < 0 or value > upper:
            raise ValueError(f"{name} must be between 0 and {upper}")

    likelihood = (
        Decimal("0.30") * values["exploitability"]
        + Decimal("0.20") * values["reachability"]
        + Decimal("0.15") * values["exposure"]
        + Decimal("0.15") * values["attack_path"]
        + Decimal("0.10") * values["threat_relevance"]
        + Decimal("0.10") * values["confidence"]
    )
    impact = (
        Decimal("0.30") * values["business_impact"]
        + Decimal("0.25") * values["data_sensitivity"]
        + Decimal("0.20") * values["regulatory_impact"]
        + Decimal("0.15") * values["asset_criticality"]
        + Decimal("0.10") * values["blast_radius"]
    )
    inherent = min(Decimal("100"), Decimal("4") * likelihood * impact)
    control_reduction = min(Decimal("0.60"), Decimal("0.12") * values["control_effectiveness"])
    residual = inherent * (Decimal("1") - control_reduction)
    confidence_factor = Decimal("0.5") + Decimal("0.1") * values["confidence"]
    age_factor = min(Decimal("1.25"), Decimal("1") + values["age_days"] / Decimal("1460"))
    priority = min(Decimal("100"), residual * confidence_factor * age_factor)

    def quantize(number):
        return number.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    return Score(quantize(inherent), quantize(residual), quantize(priority))
