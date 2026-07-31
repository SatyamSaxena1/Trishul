#!/usr/bin/env python3
"""Fail closed unless the configured OCI runtime can enforce the analyzer sandbox."""

import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

DIGEST_IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
SECRET_NAMES = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|DATABASE|DB_|OIDC|MODEL|AI_|S3_|BACKUP|REDIS)",
    re.IGNORECASE,
)


def fail(message):
    raise RuntimeError(message)


def run(cli, *arguments, timeout=120, capture=True):
    return subprocess.run(  # noqa: S603 - CLI is fixed by the installer and arguments are not shell parsed.
        [cli, *arguments],
        check=True,
        timeout=timeout,
        text=True,
        capture_output=capture,
        shell=False,
        env={**os.environ, "DOCKER_CONTENT_TRUST": "1"},
    )


def verify_inspect(data, volume):
    config = data["Config"]
    host = data["HostConfig"]
    checks = {
        "network_disabled": host.get("NetworkMode") == "none",
        "no_sensitive_environment": not any(
            SECRET_NAMES.search(item.split("=", 1)[0]) for item in config.get("Env") or []
        ),
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "capabilities_dropped": set(host.get("CapDrop") or []) == {"ALL"} and not host.get("CapAdd"),
        "not_privileged": host.get("Privileged") is False,
        "no_privilege_escalation": "no-new-privileges" in (host.get("SecurityOpt") or []),
        "cpu_bounded": host.get("NanoCpus") == 2_000_000_000,
        "memory_bounded": host.get("Memory") == 4 * 1024**3 and host.get("MemorySwap") == 4 * 1024**3,
        "pids_bounded": host.get("PidsLimit") == 256,
        "disk_bounded": "size=2g" in (host.get("Tmpfs") or {}).get("/tmp", "")  # noqa: S108
        and "size=11m" in (host.get("Tmpfs") or {}).get("/output", ""),
        "expected_user": config.get("User") == "65532:65532",
        "expected_command": config.get("Cmd") == ["/input/repository.archive", "/output/results.json"],
    }
    mounts = data.get("Mounts") or []
    checks["input_only_mount"] = len(mounts) == 1 and all(
        mount.get("Name") == volume
        and mount.get("Destination") == "/input"
        and mount.get("Type") == "volume"
        and mount.get("RW") is False
        for mount in mounts
    )
    checks["no_host_socket"] = all(
        mount.get("Destination") not in {"/run/docker.sock", "/var/run/docker.sock", "/run/oci.sock"}
        for mount in mounts
    )
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        fail("required analyzer controls were not applied: " + ", ".join(failed))
    return sorted(checks)


def main():
    cli = os.getenv("OCI_CLI", "docker")
    image = os.environ.get("TRISHUL_ANALYZER_IMAGE", "")
    if Path(cli).name not in {"docker", "podman"}:
        fail("OCI_CLI must be docker or podman")
    if not DIGEST_IMAGE.fullmatch(image):
        fail("TRISHUL_ANALYZER_IMAGE must use a sha256 digest with 64 lowercase hexadecimal characters")

    security_options = json.loads(run(cli, "info", "--format", "{{json .SecurityOptions}}").stdout)
    if not any("rootless" in str(option).lower() for option in security_options or []):
        fail("the configured OCI socket is rootful; a runtime reporting rootless mode is required")
    run(cli, "image", "inspect", image)

    suffix = uuid.uuid4().hex
    volume = f"trishul-isolation-input-{suffix}"
    helper = f"trishul-isolation-copy-{suffix}"
    container = f"trishul-isolation-test-{suffix}"
    with tempfile.TemporaryDirectory(prefix="trishul-isolation-") as directory:
        archive = Path(directory) / "empty.tar"
        # An empty tar header exercises the analyzer without storing or printing repository content.
        archive.write_bytes(b"\0" * 10240)
        try:
            run(cli, "volume", "create", volume)
            run(cli, "create", "--name", helper, "--volume", f"{volume}:/input", image)
            run(cli, "cp", str(archive), f"{helper}:/input/repository.archive")
            run(cli, "rm", "--force", helper)
            run(
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
                f"{volume}:/input:ro",
                image,
                "/input/repository.archive",
                "/output/results.json",
            )
            inspection = json.loads(run(cli, "inspect", container).stdout)[0]
            passed = verify_inspect(inspection, volume)
            run(cli, "start", "--attach", container, timeout=60)
            print(json.dumps({"analyzer_isolation": "passed", "checks": passed}, sort_keys=True))
        finally:
            subprocess.run(  # noqa: S603 - validated OCI CLI and generated object names.
                [cli, "rm", "--force", helper, container], check=False, capture_output=True
            )
            subprocess.run(  # noqa: S603 - validated OCI CLI and generated volume name.
                [cli, "volume", "rm", "--force", volume], check=False, capture_output=True
            )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"analyzer isolation verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
