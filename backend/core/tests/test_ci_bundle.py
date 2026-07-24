import json

import pytest

from scripts.trishul_ci_bundle import junit_bundle, zap_bundle


def test_ci_bundles_keep_only_hashed_evidence(tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuite tests="2" failures="1" errors="0" skipped="0" time="1.5"/>', encoding="utf-8")
    tests = junit_bundle(junit, "a" * 40)
    assert tests["coverage"]["tests"] == 2
    assert len(tests["coverage"]["artifact_hash"]) == 64

    zap = tmp_path / "zap.json"
    zap.write_text(
        json.dumps(
            {
                "@version": "2.16",
                "site": [
                    {
                        "alerts": [
                            {
                                "pluginid": "10001",
                                "name": "Header",
                                "riskcode": "2",
                                "confidence": "2",
                                "instances": [
                                    {
                                        "uri": "https://staging.example.com/",
                                        "method": "GET",
                                        "evidence": "sensitive response bytes",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    finding = zap_bundle(zap, "a" * 40, "https://staging.example.com")["findings"][0]
    assert "sensitive response bytes" not in str(finding)
    assert len(finding["evidence"][0]["location"]["response_evidence_hash"]) == 64


def test_junit_bundle_rejects_document_types(tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text("<!DOCTYPE testsuite><testsuite/>", encoding="utf-8")
    with pytest.raises(ValueError):
        junit_bundle(junit, "a" * 40)
