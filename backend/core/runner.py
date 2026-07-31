import json
import os
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings
from jsonschema import validate

from .storage import download_file

RESULT_SCHEMA = {
    "type": "object",
    "required": ["pack", "pack_version", "coverage", "findings"],
    "properties": {
        "pack": {"const": "python-stdlib"},
        "pack_version": {"const": "1.0"},
        "coverage": {"type": "object"},
        "findings": {
            "type": "array",
            "maxItems": 10000,
            "items": {
                "type": "object",
                "required": [
                    "rule_id",
                    "rule_version",
                    "title",
                    "description",
                    "cwe",
                    "asvs",
                    "severity",
                    "confidence",
                    "status",
                    "remediation",
                    "fingerprint",
                    "file_path",
                    "start_line",
                    "end_line",
                    "snippet_hash",
                ],
            },
        },
    },
}

MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_RESULT_BYTES = 10 * 1024 * 1024
ANALYZER_TIMEOUT_SECONDS = 1800


def analyzer_create_command(cli, *, container, image, input_volume):
    """Build the analyzer sandbox command; installation verification mirrors these controls."""
    return [
        cli,
        "create",
        "--name",
        container,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=4g",
        "--memory-swap=4g",
        "--cpus=2",
        "--user=65532:65532",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=2g,mode=0700,uid=65532,gid=65532",
        "--tmpfs=/output:rw,noexec,nosuid,size=11m,mode=0700,uid=65532,gid=65532",
        "--volume",
        f"{input_volume}:/input:ro",
        image,
        "/input/repository.archive",
        "/output/results.json",
    ]


def _run(command, *, timeout=120, capture=False):
    return subprocess.run(  # noqa: S603 - executable is restricted; arguments are never shell parsed.
        command,
        check=True,
        timeout=timeout,
        text=True,
        capture_output=capture,
        shell=False,
        env={**os.environ, "DOCKER_CONTENT_TRUST": "1"},
    )


def analyze(*, repository_version, scan_id):
    if os.getenv("RUNNER_BACKEND", "oci") == "kubernetes":
        from .kubernetes_runner import analyze as kubernetes_analyze

        return kubernetes_analyze(repository_version=repository_version, scan_id=scan_id)
    cli = os.getenv("OCI_CLI", "docker")
    if Path(cli).name not in {"docker", "podman", "docker.exe", "podman.exe"}:
        raise RuntimeError("OCI_CLI must be docker or podman")
    image = os.getenv("ANALYZER_IMAGE", "trishul-analyzer:development")
    if not settings.DEBUG and "@sha256:" not in image:
        raise RuntimeError("ANALYZER_IMAGE must be pinned by digest outside development")
    volume = f"trishul-job-input-{scan_id}"
    container = f"trishul-analyzer-{scan_id}"
    with tempfile.TemporaryDirectory(prefix="trishul-controller-") as directory:
        archive_path = Path(directory) / "input.archive"
        result_path = Path(directory) / "results.json"
        download_file(repository_version.object_key, str(archive_path))
        if archive_path.stat().st_size > MAX_INPUT_BYTES:
            raise RuntimeError("Analyzer input exceeds 100 MiB")
        try:
            _run([cli, "volume", "create", volume])
            helper = f"{container}-input"
            _run([cli, "create", "--name", helper, "--volume", f"{volume}:/input", image])
            try:
                _run([cli, "cp", str(archive_path), f"{helper}:/input/repository.archive"])
            finally:
                subprocess.run(  # noqa: S603 - validated OCI CLI and generated helper name.
                    [cli, "rm", "--force", helper], check=False, capture_output=True, shell=False
                )
            _run(analyzer_create_command(cli, container=container, image=image, input_volume=volume))
            _run([cli, "start", "--attach", container], timeout=ANALYZER_TIMEOUT_SECONDS, capture=True)
            _run([cli, "cp", f"{container}:/output/results.json", str(result_path)])
            if result_path.stat().st_size > MAX_RESULT_BYTES:
                raise RuntimeError("Analyzer result exceeds 10 MiB")
            result = json.loads(result_path.read_text(encoding="utf-8"))
            validate(result, RESULT_SCHEMA)
            return result
        finally:
            subprocess.run(  # noqa: S603 - validated OCI CLI and generated container name.
                [cli, "rm", "--force", container], check=False, capture_output=True, shell=False
            )
            subprocess.run(  # noqa: S603 - validated OCI CLI and generated volume name.
                [cli, "volume", "rm", "--force", volume], check=False, capture_output=True, shell=False
            )
