import json
from pathlib import Path
from types import SimpleNamespace

from analyzer.main import scan_python, scan_semgrep, scan_trivy


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


def test_semgrep_and_trivy_results_are_normalized(monkeypatch, tmp_path: Path):
    source = tmp_path / "app.tsx"
    source.write_text("<div dangerouslySetInnerHTML={{__html: value}} />", encoding="utf-8")
    semgrep = {
        "results": [
            {
                "check_id": "TRISHUL-REACT-001",
                "path": str(source),
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "message": "raw HTML",
                    "severity": "WARNING",
                    "metadata": {"cwe": "CWE-79", "confidence": "HIGH", "technology": ["react"]},
                },
            }
        ]
    }
    trivy = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                        "PkgIdentifier": {"PURL": "pkg:npm/example@1.0"},
                    }
                ],
            }
        ]
    }
    outputs = iter((semgrep, trivy))
    monkeypatch.setattr(
        "analyzer.main.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps(next(outputs))),
    )
    static = scan_semgrep(tmp_path)
    dependencies = scan_trivy(tmp_path)
    assert static[0]["evidence"][0]["evidence_type"] == "source"
    assert dependencies[0]["evidence"][0]["evidence_type"] == "dependency"
