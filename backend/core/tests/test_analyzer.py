from pathlib import Path

from analyzer.main import scan_python
from core import runner


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


def test_deployment_normalizer_uses_the_existing_hardened_runtime(monkeypatch):
    calls = []

    def download(_key, filename):
        Path(filename).write_bytes(b"{}")

    def execute(command, **_kwargs):
        calls.append(command)
        if command[1:3] == ["cp", "trishul-analyzer-abcd:/output/result.json"]:
            Path(command[-1]).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(runner, "download_file", download)
    monkeypatch.setattr(runner, "_run", execute)
    monkeypatch.setattr(runner.subprocess, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("ANALYZER_IMAGE", "registry/analyzer@sha256:" + "a" * 64)
    runner._run_isolated_oci(
        object_key="tenant/input",
        identifier="abcd",
        arguments=["normalize", "terraform_plan", "/input/artifact", "/output/result.json", "aws"],
        max_output=1024,
        timeout=120,
    )
    create = next(command for command in calls if command[1] == "create" and "--pids-limit=256" in command)
    assert "--network=none" in create
    assert "--read-only" in create
    assert "--cap-drop=ALL" in create
    assert "--pids-limit=256" in create
    assert "--memory=4g" in create
    assert "--cpus=2" in create
    assert "trishul-job-abcd-input:/input:ro" in create
    assert "normalize" in create
