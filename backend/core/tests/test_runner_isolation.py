import importlib.util
from pathlib import Path

from core.runner import analyzer_create_command


def _verifier():
    path = Path(__file__).parents[3] / "scripts" / "verify_analyzer_isolation.py"
    spec = importlib.util.spec_from_file_location("verify_analyzer_isolation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_analyzer_command_applies_resource_and_filesystem_boundaries():
    command = analyzer_create_command(
        "docker", container="sandbox", image="analyzer@sha256:digest", input_volume="input"
    )

    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--memory=4g" in command
    assert "--memory-swap=4g" in command
    assert "--cpus=2" in command
    assert "--pids-limit=256" in command
    assert "input:/input:ro" in command
    assert command[-2:] == ["/input/repository.archive", "/output/results.json"]


def test_verification_accepts_only_the_expected_effective_configuration():
    verifier = _verifier()
    inspection = {
        "Config": {
            "User": "65532:65532",
            "Cmd": ["/input/repository.archive", "/output/results.json"],
            "Env": ["PATH=/usr/local/bin"],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "Privileged": False,
            "SecurityOpt": ["no-new-privileges"],
            "NanoCpus": 2_000_000_000,
            "Memory": 4 * 1024**3,
            "MemorySwap": 4 * 1024**3,
            "PidsLimit": 256,
            "Tmpfs": {"/tmp": "rw,size=2g", "/output": "rw,size=11m"},  # noqa: S108
        },
        "Mounts": [{"Name": "input", "Destination": "/input", "Type": "volume", "RW": False}],
    }

    passed = verifier.verify_inspect(inspection, "input")

    assert "no_host_socket" in passed
    assert "no_sensitive_environment" in passed
