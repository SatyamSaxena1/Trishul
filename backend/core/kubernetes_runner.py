import json
import os
import tempfile
import time
from contextlib import suppress
from pathlib import Path

import httpx
from django.conf import settings
from jsonschema import validate

from .runner import RESULT_SCHEMA
from .storage import delete_file, download_file, presigned_get, presigned_put

MAX_ARCHIVE = 250 * 1024 * 1024
MAX_RESULT = 10 * 1024 * 1024


class KubernetesRunnerError(RuntimeError):
    pass


def _image(name):
    image = os.environ[name]
    if not settings.DEBUG and "@sha256:" not in image:
        raise KubernetesRunnerError(f"{name} must be pinned by digest")
    return image


class KubernetesAPI:
    def __init__(self):
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        port = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text().strip()
        self.namespace = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read_text().strip()
        self.client = httpx.Client(
            base_url=f"https://{host}:{port}",
            headers={"Authorization": f"Bearer {token}"},
            verify="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            timeout=15,
            follow_redirects=False,
        )

    def request(self, method, path, *, body=None, allow_not_found=False):
        response = self.client.request(method, path, json=body)
        if allow_not_found and response.status_code == 404:
            return {}
        if response.status_code >= 400:
            raise KubernetesRunnerError(
                f"Kubernetes API {method} {path} failed with {response.status_code}"
            )
        return response.json() if response.content else {}

    def create_job(self, body):
        return self.request(
            "POST", f"/apis/batch/v1/namespaces/{self.namespace}/jobs", body=body
        )

    def create_pvc(self, body):
        return self.request(
            "POST", f"/api/v1/namespaces/{self.namespace}/persistentvolumeclaims", body=body
        )

    def wait_job(self, name, timeout):
        deadline = time.monotonic() + timeout
        path = f"/apis/batch/v1/namespaces/{self.namespace}/jobs/{name}"
        while time.monotonic() < deadline:
            status = self.request("GET", path).get("status", {})
            if status.get("succeeded") == 1:
                return
            if status.get("failed"):
                raise KubernetesRunnerError(f"Kubernetes job {name} failed")
            time.sleep(2)
        raise KubernetesRunnerError(f"Kubernetes job {name} exceeded its deadline")

    def cleanup(self, name):
        options = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "propagationPolicy": "Background",
        }
        self.request(
            "DELETE",
            f"/apis/batch/v1/namespaces/{self.namespace}/jobs/{name}",
            body=options,
            allow_not_found=True,
        )

    def cleanup_pvc(self, name):
        self.request(
            "DELETE",
            f"/api/v1/namespaces/{self.namespace}/persistentvolumeclaims/{name}",
            allow_not_found=True,
        )


def _security_context(uid):
    context = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    if os.getenv("KUBE_ENFORCE_IMAGE_UID", "false").lower() == "true":
        context["runAsUser"] = uid
    return context


def _job(name, role, image, command, pvc, *, cpu="500m", memory="512Mi", deadline=900):
    body = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "labels": {"app.kubernetes.io/name": "ai-trishul", "trishul.ai/role": role}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": deadline,
            "ttlSecondsAfterFinished": 300,
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": "ai-trishul", "trishul.ai/role": role}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [
                        {
                            "name": role,
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": command,
                            "securityContext": _security_context(65532 if role == "analyzer" else 10001),
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "128Mi"},
                                "limits": {"cpu": cpu, "memory": memory},
                            },
                            "volumeMounts": [{"name": "work", "mountPath": "/work"}],
                        }
                    ],
                    "volumes": [{"name": "work", "persistentVolumeClaim": {"claimName": pvc}}],
                },
            },
        },
    }
    fs_group = os.getenv("KUBE_FS_GROUP")
    if fs_group:
        body["spec"]["template"]["spec"]["securityContext"]["fsGroup"] = int(fs_group)
        body["spec"]["template"]["spec"]["securityContext"]["fsGroupChangePolicy"] = "OnRootMismatch"
    return body


def analyze(*, repository_version, scan_id, pack):
    api = KubernetesAPI()
    suffix = str(scan_id).replace("-", "")[:20]
    pvc = f"scan-{suffix}"
    stage = f"stage-{suffix}"
    analyzer = f"analyze-{suffix}"
    collect = f"collect-{suffix}"
    result_key = f"{repository_version.tenant_id}/scan-results/{scan_id}.json"
    storage_class = os.getenv("KUBE_SCRATCH_STORAGE_CLASS")
    pvc_spec = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": pvc, "labels": {"app.kubernetes.io/name": "ai-trishul"}},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": os.getenv("KUBE_SCRATCH_SIZE", "2Gi")}},
        },
    }
    if storage_class:
        pvc_spec["spec"]["storageClassName"] = storage_class
    transfer_image = _image("KUBE_TRANSFER_IMAGE")
    analyzer_image = _image("ANALYZER_IMAGE")
    api.create_pvc(pvc_spec)
    try:
        api.create_job(
            _job(
                stage,
                "stager",
                transfer_image,
                [
                    "python",
                    "-m",
                    "core.kube_transfer",
                    "download",
                    presigned_get(repository_version.object_key),
                    "/work/input.archive",
                    "--maximum",
                    str(MAX_ARCHIVE),
                ],
                pvc,
            )
        )
        api.wait_job(stage, 900)
        api.create_job(
            _job(
                analyzer,
                "analyzer",
                analyzer_image,
                ["python", "/app/main.py", "/work/input.archive", "/work/results.json", pack],
                pvc,
                cpu="2",
                memory="4Gi",
                deadline=1800,
            )
        )
        api.wait_job(analyzer, 1800)
        api.create_job(
            _job(
                collect,
                "collector",
                transfer_image,
                [
                    "python",
                    "-m",
                    "core.kube_transfer",
                    "upload",
                    presigned_put(result_key),
                    "/work/results.json",
                    "--maximum",
                    str(MAX_RESULT),
                ],
                pvc,
            )
        )
        api.wait_job(collect, 900)
        with tempfile.TemporaryDirectory(prefix="trishul-kube-result-") as directory:
            result_path = Path(directory) / "result.json"
            download_file(result_key, str(result_path))
            result = json.loads(result_path.read_text(encoding="utf-8"))
        validate(result, RESULT_SCHEMA)
        return result
    finally:
        for job in (stage, analyzer, collect):
            api.cleanup(job)
        api.cleanup_pvc(pvc)
        with suppress(Exception):
            delete_file(result_key)
