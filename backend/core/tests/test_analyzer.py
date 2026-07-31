from pathlib import Path

from analyzer.main import RULES, scan_python


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


def test_enabled_rule_identifiers_are_versioned_contract():
    assert set(RULES) == {"PY001", "PY002", "PY003"}


def test_python_pack_recognizes_documented_call_shapes(tmp_path: Path):
    source = tmp_path / "supported.py"
    source.write_text(
        "import os\n"
        "import subprocess\n"
        "import requests\n"
        "import httpx\n"
        "import yaml\n"
        "os.system('id')\n"
        "subprocess.call('id', shell=True)\n"
        "subprocess.Popen('id', shell=True)\n"
        "requests.post('https://example.test', verify=False)\n"
        "requests.put('https://example.test', verify=False)\n"
        "requests.delete('https://example.test', verify=False)\n"
        "httpx.get('https://example.test', verify=False)\n"
        "httpx.post('https://example.test', verify=False)\n"
        "yaml.load('value', Loader=yaml.FullLoader)\n",
        encoding="utf-8",
    )

    findings, parsed = scan_python(source, "supported.py")

    assert parsed
    assert [item["rule_id"] for item in findings] == [
        "PY001",
        "PY001",
        "PY001",
        "PY002",
        "PY002",
        "PY002",
        "PY002",
        "PY002",
        "PY003",
    ]


def test_python_pack_skips_documented_blind_spots(tmp_path: Path):
    source = tmp_path / "blind_spots.py"
    source.write_text(
        "import subprocess as sp\n"
        "from requests import get\n"
        "flag = False\n"
        "sp.run('id', shell=True)\n"
        "get('https://example.test', verify=False)\n"
        "requests.get('https://example.test', verify=flag)\n",
        encoding="utf-8",
    )

    findings, parsed = scan_python(source, "blind_spots.py")

    assert parsed
    assert findings == []
