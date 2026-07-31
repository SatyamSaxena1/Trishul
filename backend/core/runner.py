import json
import os
import subprocess
import tempfile
import time
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


def analyzer_resources(scan_id):
    """Return stable names so resources survive controller and host-process restarts."""
    return f"trishul-analyzer-{scan_id}", f"trishul-job-{scan_id}"


def _oci_cli():
    cli = os.getenv("OCI_CLI", "docker")
    if Path(cli).name not in {"docker", "podman", "docker.exe", "podman.exe"}:
        raise RuntimeError("OCI_CLI must be docker or podman")
    return cli


def analyzer_status(scan_id):
    """Return active/inactive/unknown; unknown must never be treated as safe to retry."""
    if os.getenv("RUNNER_BACKEND", "oci") == "kubernetes":
        from .kubernetes_runner import analyzer_status as kubernetes_status

        return kubernetes_status(scan_id)
    try:
        cli = _oci_cli()
    except RuntimeError:
        return "unknown"
    container, _ = analyzer_resources(scan_id)
    try:
        result = subprocess.run(  # noqa: S603 - CLI is validated by analyze; arguments are not shell parsed.
            [cli, "inspect", "--format", "{{.State.Running}}", container],
            check=False, capture_output=True, text=True, timeout=15, shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if result.returncode != 0:
        return "inactive" if "No such" in result.stderr or "no such" in result.stderr else "unknown"
    return "active" if result.stdout.strip().lower() == "true" else "inactive"


def cleanup_resources(scan_id):
    """Remove scratch only after the caller has established the analyzer is inactive."""
    if os.getenv("RUNNER_BACKEND", "oci") == "kubernetes":
        from .kubernetes_runner import cleanup_resources as kubernetes_cleanup

        return kubernetes_cleanup(scan_id)
    cli = _oci_cli()
    container, volume = analyzer_resources(scan_id)
    for command in ([cli, "rm", "--force", container], [cli, "volume", "rm", "--force", volume]):
        subprocess.run(command, check=False, capture_output=True, shell=False)  # noqa: S603


def analyze(*, repository_version, scan_id, heartbeat=None):
    if os.getenv("RUNNER_BACKEND", "oci") == "kubernetes":
        from .kubernetes_runner import analyze as kubernetes_analyze

        return kubernetes_analyze(repository_version=repository_version, scan_id=scan_id, heartbeat=heartbeat)
    cli = _oci_cli()
    image = os.getenv("ANALYZER_IMAGE", "trishul-analyzer:development")
    if not settings.DEBUG and "@sha256:" not in image:
        raise RuntimeError("ANALYZER_IMAGE must be pinned by digest outside development")
    container, volume = analyzer_resources(scan_id)
    with tempfile.TemporaryDirectory(prefix="trishul-controller-") as directory:
        archive_path = Path(directory) / "input.archive"
        result_path = Path(directory) / "results.json"
        download_file(repository_version.object_key, str(archive_path))
        if heartbeat:
            heartbeat()
        try:
            _run([cli, "volume", "create", volume])
            if heartbeat:
                heartbeat()
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
            if heartbeat:
                heartbeat()
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
            # This fenced heartbeat closes the inspect/start race with reconciliation:
            # after a lease is reclaimed an old controller cannot start its container.
            if heartbeat:
                heartbeat()
            process = subprocess.Popen(  # noqa: S603
                [cli, "start", "--attach", container], text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False,
            )
            deadline = time.monotonic() + 1800
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    process.kill()
                    raise subprocess.TimeoutExpired(process.args, 1800)
                if heartbeat:
                    heartbeat()
                time.sleep(10)
            stdout, stderr = process.communicate()
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, process.args, stdout, stderr)
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
