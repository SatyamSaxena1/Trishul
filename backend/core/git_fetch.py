import io
import os
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx
import jwt
from django.conf import settings
from django.db import transaction

from .archive import inspect_archive
from .credentials import decrypt_credential
from .integrations import validate_clone_url, validate_commit
from .models import AuditEvent, Repository, RepositoryVersion
from .storage import put_file

GIT = shutil.which("git") or "git"


def _github_token(repository):
    if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
        raise RuntimeError("GitHub App credentials are not configured.")
    now = int(time.time())
    assertion = jwt.encode(
        {"iat": now - 30, "exp": now + 540, "iss": settings.GITHUB_APP_ID},
        settings.GITHUB_APP_PRIVATE_KEY,
        algorithm="RS256",
    )
    url = f"{settings.GITHUB_API_URL.rstrip('/')}/app/installations/{repository.installation_id}/access_tokens"
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        response = client.post(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {assertion}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response.raise_for_status()
        return response.json()["token"], "x-access-token"


def _credential(repository):
    if repository.source_type == Repository.SourceType.GITHUB:
        return _github_token(repository)
    if repository.source_type == Repository.SourceType.GITLAB:
        return decrypt_credential(repository.credential_ciphertext), "oauth2"
    raise RuntimeError("Only GitHub and GitLab repositories can be fetched.")


def _run_git(arguments, directory, environment, timeout=300):
    try:
        subprocess.run(  # noqa: S603 - arguments are validated and never shell parsed.
            [GIT, "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", *arguments],
            cwd=directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Git fetch failed.") from exc


def fetch_archive(repository, commit_sha):
    validate_clone_url(repository.source_type, repository.clone_url)
    commit_sha = validate_commit(commit_sha)
    token, username = _credential(repository)
    with tempfile.TemporaryDirectory(prefix="trishul-fetch-") as directory:
        root = Path(directory)
        checkout = root / "repository"
        checkout.mkdir()
        askpass = root / "askpass.py"
        askpass.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            "print(os.environ['TRISHUL_GIT_USER'] if 'sername' in sys.argv[1] else os.environ['TRISHUL_GIT_TOKEN'])\n",
            encoding="utf-8",
        )
        askpass.chmod(stat.S_IRUSR | stat.S_IXUSR)
        environment = {
            **os.environ,
            "GIT_ASKPASS": str(askpass),
            "GIT_TERMINAL_PROMPT": "0",
            "TRISHUL_GIT_TOKEN": token,
            "TRISHUL_GIT_USER": username,
        }
        _run_git(["init", "--quiet"], checkout, environment)
        _run_git(["remote", "add", "origin", repository.clone_url], checkout, environment)
        _run_git(["fetch", "--quiet", "--depth=1", "--no-tags", "origin", commit_sha], checkout, environment, 600)
        resolved = subprocess.run(  # noqa: S603 - fixed git operation in an isolated checkout.
            [GIT, "rev-parse", "FETCH_HEAD"],
            cwd=checkout,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        if resolved != commit_sha:
            raise RuntimeError("Git provider returned a different commit.")
        archive_path = root / "repository.tar"
        _run_git(["archive", "--format=tar", f"--output={archive_path}", "FETCH_HEAD"], checkout, environment, 600)
        with archive_path.open("rb") as archive:
            manifest = inspect_archive(archive)
        return archive_path.read_bytes(), manifest


def persist_version(repository, commit_sha, ref, event):
    data, manifest = fetch_archive(repository, commit_sha)
    key = f"{repository.tenant_id}/repositories/{repository.id}/{commit_sha}.tar"
    put_file(key, io.BytesIO(data), content_type="application/x-tar")
    with transaction.atomic():
        version, created = RepositoryVersion.all_objects.get_or_create(
            tenant=repository.tenant,
            repository=repository,
            sha256=manifest["sha256"],
            commit_sha=commit_sha,
            defaults={
                "object_key": key,
                "size": len(data),
                "manifest": manifest,
                "ref": ref,
                "source_event": event,
            },
        )
        if created:
            AuditEvent.append(
                tenant=repository.tenant,
                actor_type="system",
                actor_id="repository-fetcher",
                action="repository.fetched",
                resource_type="core.repositoryversion",
                resource_id=version.id,
                details={"repository_id": str(repository.id), "commit_sha": commit_sha, "ref": ref},
            )
    return version, created


def publish_status(version, finding_count):
    repository = version.repository
    token, _ = _credential(repository)
    description = f"Advisory scan complete: {finding_count} finding{'s' if finding_count != 1 else ''}"
    target_url = (
        f"{settings.TRISHUL_PUBLIC_URL.rstrip('/')}/repository-versions/{version.id}"
        if settings.TRISHUL_PUBLIC_URL
        else ""
    )
    if repository.source_type == Repository.SourceType.GITHUB:
        path = urlparse(repository.clone_url).path.removesuffix(".git").strip("/")
        url = f"{settings.GITHUB_API_URL.rstrip('/')}/repos/{path}/statuses/{version.commit_sha}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        payload = {
            "state": "success",
            "context": "AI Trishul (advisory)",
            "description": description[:140],
            "target_url": target_url,
        }
    else:
        if not repository.status_credential_ciphertext:
            return
        token = decrypt_credential(repository.status_credential_ciphertext)
        url = (
            f"{settings.GITLAB_API_URL.rstrip('/')}/projects/{quote(repository.external_id, safe='')}"
            f"/statuses/{version.commit_sha}"
        )
        headers = {"PRIVATE-TOKEN": token}
        payload = {
            "state": "success",
            "name": "AI Trishul (advisory)",
            "description": description[:255],
            "target_url": target_url,
        }
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()
