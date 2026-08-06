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

NORMALIZED_SCHEMA = {
    "type": "object",
    "required": ["schema_version", "provider", "source_type", "resource_count", "metadata", "resources"],
    "properties": {
        "schema_version": {"const": "trishul-normalized-snapshot/1.0"},
        "provider": {"type": "string"},
        "source_type": {"type": "string"},
        "resource_count": {"type": "integer", "minimum": 0, "maximum": 20000},
        "metadata": {"type": "object"},
        "resources": {
            "type": "array",
            "maxItems": 20000,
            "items": {
                "type": "object",
                "required": [
                    "schema_version",
                    "provider",
                    "resource_type",
                    "resource_id",
                    "name",
                    "source_path",
                    "labels",
                    "attributes",
                    "relationships",
                ],
                "properties": {
                    "schema_version": {"const": "trishul-resource/1.0"},
                    "provider": {"type": "string"},
                    "resource_type": {"type": "string"},
                    "resource_id": {"type": "string"},
                    "name": {"type": "string"},
                    "source_path": {"type": "string"},
                    "labels": {"type": "object"},
                    "attributes": {"type": "object"},
                    "relationships": {"type": "array"},
                },
                "additionalProperties": False,
            },
        },
    },
    "additionalProperties": False,
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


def _run_isolated_oci(*, object_key, identifier, arguments, max_output, timeout):
    """Run one analyzer-image command with the shared hardened OCI boundary."""
    cli = os.getenv("OCI_CLI", "docker")
    if Path(cli).name not in {"docker", "podman", "docker.exe", "podman.exe"}:
        raise RuntimeError("OCI_CLI must be docker or podman")
    image = os.getenv("ANALYZER_IMAGE", "trishul-analyzer:development")
    if not settings.DEBUG and "@sha256:" not in image:
        raise RuntimeError("ANALYZER_IMAGE must be pinned by digest outside development")
    safe_id = str(identifier).replace("-", "")[:24]
    input_volume = f"trishul-job-{safe_id}-input"
    output_volume = f"trishul-job-{safe_id}-output"
    container = f"trishul-analyzer-{safe_id}"
    stager = f"{container}-stage"
    with tempfile.TemporaryDirectory(prefix="trishul-controller-") as directory:
        input_path = Path(directory) / "input"
        result_path = Path(directory) / "result.json"
        download_file(object_key, str(input_path))
        try:
            _run([cli, "volume", "create", input_volume])
            _run([cli, "volume", "create", output_volume])
            _run(
                [
                    cli,
                    "create",
                    "--name",
                    stager,
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--entrypoint=python",
                    "--user=0:0",
                    "--volume",
                    f"{input_volume}:/input",
                    "--volume",
                    f"{output_volume}:/output",
                    image,
                    "-c",
                    "import os; os.chown('/input/artifact',65532,65532); os.chmod('/input/artifact',0o444); "
                    "os.chown('/output',65532,65532)",
                ]
            )
            _run([cli, "cp", str(input_path), f"{stager}:/input/artifact"])
            _run([cli, "start", "--attach", stager])
            _run([cli, "rm", stager])
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
                    f"{input_volume}:/input:ro",
                    "--volume",
                    f"{output_volume}:/output",
                    image,
                    *arguments,
                ]
            )
            _run([cli, "start", "--attach", container], timeout=timeout, capture=True)
            _run([cli, "cp", f"{container}:/output/result.json", str(result_path)])
            if result_path.stat().st_size > max_output:
                raise RuntimeError(f"Analyzer result exceeds {max_output} bytes")
            return result_path.read_bytes()
        finally:
            subprocess.run([cli, "rm", "--force", stager], check=False, capture_output=True, shell=False)  # noqa: S603
            subprocess.run([cli, "rm", "--force", container], check=False, capture_output=True, shell=False)  # noqa: S603
            for volume in (input_volume, output_volume):
                subprocess.run([cli, "volume", "rm", "--force", volume], check=False, capture_output=True, shell=False)  # noqa: S603


def analyze(*, repository_version, scan_id):
    if os.getenv("RUNNER_BACKEND", "oci") == "kubernetes":
        from .kubernetes_runner import analyze as kubernetes_analyze

        return kubernetes_analyze(repository_version=repository_version, scan_id=scan_id)
    payload = _run_isolated_oci(
        object_key=repository_version.object_key,
        identifier=scan_id,
        arguments=["/input/artifact", "/output/result.json"],
        max_output=10 * 1024 * 1024,
        timeout=1800,
    )
    result = json.loads(payload)
    validate(result, RESULT_SCHEMA)
    return result


def normalize_deployment(*, snapshot, run_id):
    """Normalize untrusted deployment input in process only for local DEBUG."""
    backend = os.getenv(
        "ASSURANCE_NORMALIZER_BACKEND",
        "process" if settings.ASSURANCE_ALLOW_IN_PROCESS_NORMALIZATION else os.getenv("RUNNER_BACKEND", "oci"),
    )
    if backend == "process":
        if not settings.ASSURANCE_ALLOW_IN_PROCESS_NORMALIZATION:
            raise RuntimeError("In-process deployment normalization is disabled")
        from deployment_assurance.normalizers import normalize

        with tempfile.TemporaryDirectory(prefix="trishul-assurance-local-") as directory:
            path = Path(directory) / "input"
            download_file(snapshot.artifact_object_key, str(path))
            document = normalize(
                source_type=snapshot.source_type, payload=path.read_bytes(), provider=snapshot.target.provider
            )
    elif backend == "kubernetes":
        from .kubernetes_runner import normalize_deployment as kubernetes_normalize

        document = kubernetes_normalize(snapshot=snapshot, run_id=run_id)
    else:
        from deployment_assurance.limits import MAX_NORMALIZED_BYTES

        payload = _run_isolated_oci(
            object_key=snapshot.artifact_object_key,
            identifier=run_id,
            arguments=[
                "normalize",
                snapshot.source_type,
                "/input/artifact",
                "/output/result.json",
                snapshot.target.provider,
            ],
            max_output=MAX_NORMALIZED_BYTES,
            timeout=120,
        )
        document = json.loads(payload)
    validate(document, NORMALIZED_SCHEMA)
    if document["resource_count"] != len(document["resources"]):
        raise RuntimeError("Normalizer resource_count does not match its output")
    return document
