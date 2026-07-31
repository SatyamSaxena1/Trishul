from pathlib import Path

import pytest
from rest_framework import serializers

from analyzer.main import scan_python
from core.tasks import validate_analyzer_output


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
    assert all(item["analyzer_name"] == "trishul-python-ast" for item in findings)
    assert all(item["remediation"] and item["evidence"] for item in findings)
    output = {
        "pack": "python-stdlib",
        "pack_version": "1.0",
        "analyzer": {"name": "trishul-python-ast", "version": "1.0", "image_digest": ""},
        "coverage": {},
        "findings": findings,
    }
    assert validate_analyzer_output(output)


def test_analyzer_output_rejects_incomplete_or_unsafe_findings(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system('id')\n", encoding="utf-8")
    findings, _ = scan_python(source, "app.py")
    findings[0]["file_path"] = "../app.py"

    with pytest.raises(serializers.ValidationError):
        validate_analyzer_output(
            {
                "pack": "python-stdlib",
                "pack_version": "1.0",
                "analyzer": {"name": "trishul-python-ast", "version": "1.0", "image_digest": ""},
                "coverage": {},
                "findings": findings,
            }
        )
