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
    "required": ["pack", "pack_version", "rule_configuration_version", "coverage", "findings"],
    "properties": {
        "pack": {"const": "python-stdlib"},
        "pack_version": {"const": "1.0"},
        "rule_configuration_version": {"type": "string", "minLength": 1},
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
    volume = f"trishul-job-{scan_id}"
    container = f"trishul-analyzer-{scan_id}"
    with tempfile.TemporaryDirectory(prefix="trishul-controller-") as directory:
        archive_path = Path(directory) / "input.archive"
        result_path = Path(directory) / "results.json"
        download_file(repository_version.object_key, str(archive_path))
        try:
            _run([cli, "volume", "create", volume])
            _run(
                [
                    cli,
                    "run",
                    "--rm",
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--entrypoint=python",
                    "--user=0:0",
                    "--volume",
                    f"{volume}:/work",
                    image,
                    "-c",
                    "import os; os.chown('/work', 65532, 65532)",
                ]
            )
            _run(
                [
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
                    "--cpus=2",
                    "--user=65532:65532",
                    "--tmpfs=/tmp:rw,noexec,nosuid,size=2g",
                    "--volume",
                    f"{volume}:/work",
                    image,
                    "/work/input.archive",
                    "/work/results.json",
                ]
            )
            _run([cli, "cp", str(archive_path), f"{container}:/work/input.archive"])
            _run([cli, "start", "--attach", container], timeout=1800, capture=True)
            _run([cli, "cp", f"{container}:/work/results.json", str(result_path)])
            if result_path.stat().st_size > 10 * 1024 * 1024:
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
