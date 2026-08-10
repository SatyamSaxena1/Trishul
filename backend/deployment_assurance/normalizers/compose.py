"""Docker Compose normalizer.

Compose is the deployment format for Trishul's own small-install profile, and
for many pilot customers it is the only infrastructure description that exists.
Services map to ``compute.container`` so the same container rules apply as for
Kubernetes, and published ports map to ``network.ingress_rule``.

Port publishing semantics matter: ``"8080:80"`` binds on all interfaces and is
therefore reachable from anywhere the host is, whereas ``"127.0.0.1:8080:80"``
is loopback-only. The normalizer distinguishes the two rather than treating
every published port as public.
"""

from typing import Any, Iterator, Mapping

from ..limits import UnsafeArtifact
from ..resources import Resource, ResourceType, normalized_document
from .detect import find_secrets
from .safeload import load_yaml_documents

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _parse_port(entry: Any) -> tuple[int | None, str]:
    """Return ``(host_port, bind_address)`` for one Compose port entry.

    Accepts both the short string form and the long mapping form.
    """
    if isinstance(entry, Mapping):
        published = entry.get("published")
        host_ip = str(entry.get("host_ip") or "")
        try:
            return (int(published) if published is not None else None), host_ip
        except (TypeError, ValueError):
            return None, host_ip
    text = str(entry).strip()
    if not text:
        return None, ""
    # Strip a protocol suffix such as "8080:80/udp".
    text = text.split("/", 1)[0]
    parts = text.split(":")
    if len(parts) == 1:
        # "80" exposes a container port on an ephemeral host port.
        return None, ""
    if len(parts) == 2:
        host_part = parts[0]
        return (int(host_part) if host_part.isdigit() else None), ""
    host_ip = ":".join(parts[:-2])
    host_part = parts[-2]
    return (int(host_part) if host_part.isdigit() else None), host_ip


def _service(name: str, definition: Mapping, provider: str) -> Iterator[Resource]:
    image = str(definition.get("image") or "")
    user = str(definition.get("user") or "")
    security_opt = [str(item) for item in definition.get("security_opt") or ()]
    cap_add = [str(item) for item in definition.get("cap_add") or ()]
    deploy_limits = ((definition.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    host_paths = []
    for volume in definition.get("volumes") or ():
        if isinstance(volume, Mapping) and str(volume.get("type")) == "bind":
            host_paths.append(str(volume.get("source") or ""))
        elif isinstance(volume, str) and volume.startswith(("/", "./", "../")):
            host_paths.append(volume.split(":", 1)[0])

    yield Resource(
        resource_type=ResourceType.CONTAINER,
        resource_id=f"compose/{name}",
        provider=provider,
        name=name,
        source_path=f"services.{name}",
        labels={str(k): str(v) for k, v in (definition.get("labels") or {}).items()}
        if isinstance(definition.get("labels"), Mapping)
        else {},
        attributes={
            "image": image,
            "image_digest_pinned": "@sha256:" in image,
            "privileged": bool(definition.get("privileged")),
            "allow_privilege_escalation": "no-new-privileges:true" not in security_opt,
            "read_only_root_filesystem": bool(definition.get("read_only")),
            # No user directive means the image's USER applies, which defaults
            # to root for most base images.
            "runs_as_root": user in {"", "0", "root", "0:0"},
            "run_as_user": user,
            "host_network": str(definition.get("network_mode") or "") == "host",
            "host_pid": str(definition.get("pid") or "") == "host",
            "host_ipc": str(definition.get("ipc") or "") == "host",
            "host_path_mounts": sorted({path for path in host_paths if path}),
            "added_capabilities": sorted(cap_add),
            "cpu_limit": str(deploy_limits.get("cpus") or ""),
            "memory_limit": str(deploy_limits.get("memory") or ""),
            "has_resource_limits": bool(deploy_limits.get("cpus") and deploy_limits.get("memory")),
        },
    )

    published: list[int] = []
    loopback_only = True
    for entry in definition.get("ports") or ():
        host_port, host_ip = _parse_port(entry)
        if host_port is None:
            continue
        published.append(host_port)
        if host_ip not in LOOPBACK_HOSTS:
            loopback_only = False
    if published:
        yield Resource(
            resource_type=ResourceType.INGRESS_RULE,
            resource_id=f"compose/{name}#ports",
            provider=provider,
            name=name,
            source_path=f"services.{name}.ports",
            attributes={
                "ports": sorted(set(published)),
                "protocol": "tcp",
                "source_cidrs": [] if loopback_only else ["0.0.0.0/0"],
                "direction": "ingress",
                "loopback_only": loopback_only,
            },
        )


def normalize(payload: bytes, *, provider: str = "generic") -> dict:
    documents = [document for document in load_yaml_documents(payload) if isinstance(document, Mapping)]
    if not documents:
        raise UnsafeArtifact("Artifact contains no Compose document.")
    document = documents[0]
    services = document.get("services")
    if not isinstance(services, Mapping):
        raise UnsafeArtifact("Artifact is not a Compose file: no 'services' mapping.")

    resources: list[Resource] = []
    for name, definition in sorted(services.items()):
        if not isinstance(definition, Mapping):
            continue
        service_name = str(name)
        resources.extend(_service(service_name, definition, provider))
        # `environment` is where plaintext credentials most often appear; the
        # `secrets` block is a reference and is intentionally not scanned.
        resources.extend(
            find_secrets(
                definition.get("environment") or {},
                source_path=f"services.{service_name}.environment",
                owner_id=f"compose/{service_name}",
                provider=provider,
            )
        )

    return normalized_document(
        provider=provider,
        source_type="compose_file",
        resources=resources,
        metadata={"services": len(services), "normalizer": "compose"},
    )
