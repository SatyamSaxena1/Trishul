from decimal import Decimal

import pytest

from core.risk import calculate


def test_risk_score_is_deterministic_and_bounded():
    inputs = {
        "exploitability": 5,
        "reachability": 5,
        "exposure": 5,
        "attack_path": 5,
        "threat_relevance": 5,
        "confidence": 5,
        "business_impact": 5,
        "data_sensitivity": 5,
        "regulatory_impact": 5,
        "asset_criticality": 5,
        "blast_radius": 5,
        "control_effectiveness": 0,
        "age_days": 36500,
    }
    score = calculate(inputs)
    assert score.inherent == Decimal("100.00")
    assert score.residual == Decimal("100.00")
    assert score.priority == Decimal("100.00")


def test_risk_score_rejects_missing_or_out_of_range_values():
    with pytest.raises(ValueError):
        calculate({})
