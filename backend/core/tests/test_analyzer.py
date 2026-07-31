from pathlib import Path

from analyzer.main import RULES, load_rule_config, scan_python
from analyzer.quality import markdown_report, summarize_reviews


def test_python_pack_finds_only_evidence_backed_calls(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text(
        "import subprocess\n"
        "import requests\n"
        "subprocess.run('echo unsafe', shell=True)\n"
        "requests.get('https://example.test', verify=False)\n",
        encoding="utf-8",
    )
    findings, parsed = scan_python(source, "app.py")
    assert parsed
    assert [item["rule_id"] for item in findings] == ["PY001", "PY002"]
    assert all("echo unsafe" not in str(item) for item in findings)


def test_disabled_rule_stops_new_findings_without_removing_definition(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import requests\nrequests.get('https://example.test', verify=False)\n", encoding="utf-8")
    RULES["PY002"]["enabled"] = False
    try:
        findings, parsed = scan_python(source, "app.py")
    finally:
        RULES["PY002"]["enabled"] = True
    assert parsed
    assert findings == []
    assert RULES["PY002"]["rule_version"] == "1.0"


def test_rule_configuration_and_quality_report_are_versioned():
    root = Path(__file__).parents[3]
    config = load_rule_config(root / "analyzer/rules/v1.json")
    summary = summarize_reviews(root / "analyzer/regression/pilot_reviews.json")
    assert config["configuration_version"] == "1.0"
    assert [(row["rule_id"], row["usefulness_percentage"]) for row in summary["rules"]] == [
        ("PY001", 80.0),
        ("PY002", 70.0),
        ("PY003", 60.0),
    ]
    assert "| **Overall** | **30** | **21** | **4** | **1** | **4** | **70.0%** |" in markdown_report(summary)
