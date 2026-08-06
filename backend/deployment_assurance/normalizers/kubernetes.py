"""Kubernetes manifest normalizer.

Handles the multi-document YAML streams produced by ``kubectl kustomize``,
``helm template`` or a plain manifest directory. Workload kinds are unwrapped to
their pod template so that a Deployment, StatefulSet, DaemonSet, Job and CronJob
all yield the same ``compute.container`` resources — a rule about privileged
containers should not care which controller created the pod.

Security context resolution follows Kubernetes semantics: the container-level
setting wins, falling back to the pod-level setting, falling back to the
cluster default. Where the default is itself unsafe (``runAsNonRoot`` unset),
the attribute is left unknown rather than assumed safe.
"""

from typing import Any, Iterator, Mapping

from ..limits import UnsafeArtifact
from ..resources import Resource, ResourceType, normalized_document
from .detect import find_secrets
from .safeload import load_yaml_documents

WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "Pod", "CronJob"})
MUTATING_VERBS = frozenset({"*", "create", "update", "patch", "delete", "deletecollection", "impersonate", "escalate"})


def _pod_spec(kind: str, spec: Mapping) -> Mapping | None:
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job = (spec.get("jobTemplate") or {}).get("spec") or {}
        return (job.get("template") or {}).get("spec")
    return (spec.get("template") or {}).get("spec")


def _resolve(container: Mapping, pod: Mapping, key: str) -> Any:
    """Container security context wins over pod, matching Kubernetes."""
    container_context = container.get("securityContext") or {}
    if key in container_context:
        return container_context[key]
    pod_context = pod.get("securityContext") or {}
    return pod_context.get(key)


def _runs_as_root(run_as_user, run_as_non_root) -> bool:
    """Decide whether a container will run as UID 0.

    An explicit ``runAsUser`` is authoritative — including ``runAsUser: 0``,
    which requests root even when an inherited ``runAsNonRoot: true`` would
    contradict it. (Kubernetes refuses to start that combination; from an
    assurance standpoint the manifest is asking for root and should be
    reported as such rather than credited for the contradicted flag.)

    With no ``runAsUser`` at all, only ``runAsNonRoot: true`` establishes a
    non-root guarantee; otherwise the image's ``USER`` decides, and in practice
    that is root far more often than not.
    """
    if run_as_user is not None:
        try:
            return int(run_as_user) == 0
        except (TypeError, ValueError):
            return True
    return run_as_non_root is not True


def _image_pinned(image: str) -> bool:
    """A digest is pinned. A tag — including an explicit one — is mutable."""
    return "@sha256:" in image


def _containers(document: Mapping, kind: str, namespace: str, name: str, provider: str) -> Iterator[Resource]:
    pod = _pod_spec(kind, document.get("spec") or {})
    if not isinstance(pod, Mapping):
        return
    host_paths = [
        str((volume.get("hostPath") or {}).get("path", ""))
        for volume in pod.get("volumes") or ()
        if isinstance(volume, Mapping) and volume.get("hostPath")
    ]
    all_containers = [
        *(pod.get("containers") or ()),
        *(pod.get("initContainers") or ()),
        *(pod.get("ephemeralContainers") or ()),
    ]
    for container in all_containers:
        if not isinstance(container, Mapping):
            continue
        container_name = str(container.get("name") or "container")
        image = str(container.get("image") or "")
        limits = (container.get("resources") or {}).get("limits") or {}
        run_as_user = _resolve(container, pod, "runAsUser")
        run_as_non_root = _resolve(container, pod, "runAsNonRoot")
        capabilities = (container.get("securityContext") or {}).get("capabilities") or {}
        yield Resource(
            resource_type=ResourceType.CONTAINER,
            resource_id=f"{namespace}/{kind}/{name}/{container_name}",
            provider=provider,
            name=container_name,
            source_path=f"{namespace}/{kind}/{name}",
            labels={str(k): str(v) for k, v in ((document.get("metadata") or {}).get("labels") or {}).items()},
            attributes={
                "image": image,
                "image_digest_pinned": _image_pinned(image),
                "privileged": bool(_resolve(container, pod, "privileged")),
                "allow_privilege_escalation": _resolve(container, pod, "allowPrivilegeEscalation") is not False,
                "read_only_root_filesystem": bool(_resolve(container, pod, "readOnlyRootFilesystem")),
                "runs_as_root": _runs_as_root(run_as_user, run_as_non_root),
                "run_as_user": run_as_user,
                "host_network": bool(pod.get("hostNetwork")),
                "host_pid": bool(pod.get("hostPID")),
                "host_ipc": bool(pod.get("hostIPC")),
                "host_path_mounts": sorted({path for path in host_paths if path}),
                "added_capabilities": sorted(str(item) for item in capabilities.get("add") or ()),
                "cpu_limit": str(limits.get("cpu") or ""),
                "memory_limit": str(limits.get("memory") or ""),
                "has_resource_limits": bool(limits.get("cpu") and limits.get("memory")),
            },
        )


def _service(document: Mapping, namespace: str, name: str, provider: str) -> Iterator[Resource]:
    spec = document.get("spec") or {}
    if str(spec.get("type") or "ClusterIP") not in {"LoadBalancer", "NodePort"}:
        return
    ports = []
    for port in spec.get("ports") or ():
        if isinstance(port, Mapping):
            value = port.get("port") or port.get("targetPort")
            if isinstance(value, int):
                ports.append(value)
    yield Resource(
        resource_type=ResourceType.INGRESS_RULE,
        resource_id=f"{namespace}/Service/{name}",
        provider=provider,
        name=name,
        source_path=f"{namespace}/Service/{name}",
        attributes={
            "ports": sorted(set(ports)),
            "protocol": "tcp",
            # A LoadBalancer or NodePort service is reachable from outside the
            # cluster unless a network policy or cloud rule says otherwise, and
            # neither is visible in this manifest.
            "source_cidrs": ["0.0.0.0/0"],
            "direction": "ingress",
            "service_type": str(spec.get("type")),
        },
    )


def _rbac(document: Mapping, kind: str, namespace: str, name: str, provider: str) -> Iterator[Resource]:
    wildcard_verbs = False
    wildcard_resources = False
    for rule in document.get("rules") or ():
        if not isinstance(rule, Mapping):
            continue
        verbs = {str(item) for item in rule.get("verbs") or ()}
        resources = {str(item) for item in rule.get("resources") or ()}
        if "*" in verbs:
            wildcard_verbs = True
        if "*" in resources and verbs & MUTATING_VERBS:
            wildcard_resources = True
    yield Resource(
        resource_type=ResourceType.IDENTITY_POLICY,
        resource_id=f"{namespace or 'cluster'}/{kind}/{name}",
        provider=provider,
        name=name,
        source_path=f"{namespace or 'cluster'}/{kind}/{name}",
        attributes={
            "wildcard_actions": wildcard_verbs,
            "wildcard_resources": wildcard_resources,
            "document_parsed": True,
            "cluster_scoped": kind == "ClusterRole",
        },
    )


def _secret(document: Mapping, namespace: str, name: str, provider: str) -> Iterator[Resource]:
    """A committed Secret manifest carries base64 material, not a reference."""
    data = document.get("data") or {}
    string_data = document.get("stringData") or {}
    keys = sorted({*(str(key) for key in data), *(str(key) for key in string_data)})
    if not keys:
        return
    yield Resource(
        resource_type=ResourceType.SECRET_MATERIAL,
        resource_id=f"{namespace}/Secret/{name}",
        provider=provider,
        name=name,
        source_path=f"{namespace}/Secret/{name}",
        attributes={
            "attribute_path": f"{namespace}/Secret/{name}",
            "detection_reasons": ["inline_kubernetes_secret"],
            "secret_keys": keys,
            "value_length": 0,
        },
    )


def normalize(payload: bytes, *, provider: str = "kubernetes") -> dict:
    resources: list[Resource] = []
    kinds: dict[str, int] = {}
    documents = 0
    for document in load_yaml_documents(payload):
        if not isinstance(document, Mapping):
            continue
        kind = str(document.get("kind") or "")
        if not kind:
            continue
        documents += 1
        kinds[kind] = kinds.get(kind, 0) + 1
        metadata = document.get("metadata") or {}
        name = str(metadata.get("name") or "unnamed")
        namespace = str(metadata.get("namespace") or "default")
        if kind in WORKLOAD_KINDS:
            resources.extend(_containers(document, kind, namespace, name, provider))
        elif kind == "Service":
            resources.extend(_service(document, namespace, name, provider))
        elif kind in {"Role", "ClusterRole"}:
            resources.extend(_rbac(document, kind, namespace, name, provider))
        elif kind == "Secret":
            resources.extend(_secret(document, namespace, name, provider))
        if kind != "Secret":
            resources.extend(
                find_secrets(
                    document.get("spec") or {},
                    source_path=f"{namespace}/{kind}/{name}",
                    owner_id=f"{namespace}/{kind}/{name}",
                    provider=provider,
                )
            )

    if not documents:
        raise UnsafeArtifact("Artifact contains no Kubernetes objects with a 'kind' field.")

    return normalized_document(
        provider=provider,
        source_type="kubernetes_manifest",
        resources=resources,
        metadata={"documents": documents, "kinds": dict(sorted(kinds.items())), "normalizer": "kubernetes"},
    )
