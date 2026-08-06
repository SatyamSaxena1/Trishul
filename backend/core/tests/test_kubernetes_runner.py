import pytest

from core.kube_transfer import validate_url
from core.kubernetes_runner import _job


def test_analyzer_job_has_no_token_network_credentials_or_privilege():
    job = _job(
        "analyze-test",
        "analyzer",
        "registry/analyzer@sha256:" + "a" * 64,
        ["python", "/app/main.py", "/work/input.archive", "/work/results.json"],
        "scan-test",
    )
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert pod["automountServiceAccountToken"] is False
    assert "env" not in container and "envFrom" not in container
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert {"name": "work", "mountPath": "/input", "subPath": "input", "readOnly": True} in container["volumeMounts"]


@pytest.mark.parametrize(
    "url",
    [
        "http://objects.example/file",
        "file:///etc/passwd",
        "https://user:password@objects.example/file",
        "//objects.example/file",
    ],
)
def test_transfer_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        validate_url(url)
