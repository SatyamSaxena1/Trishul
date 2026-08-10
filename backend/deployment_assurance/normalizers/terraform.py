"""Terraform plan JSON normalizer.

Consumes the output of ``terraform show -json <planfile>``. The plan is the
highest-value pre-deployment artifact because it records the *resolved* state a
provider will create, not the templated source.

Two deliberate choices:

* ``resource_changes`` is preferred over ``planned_values`` because it carries
  the action list, letting us skip resources scheduled for deletion.
* An unmapped Terraform type is recorded in ``metadata.unmapped_types`` rather
  than dropped silently. Coverage is reported to the auditor; an unrecognised
  resource never counts as a pass.
"""

from typing import Any, Iterator, Mapping

from ..limits import UnsafeArtifact
from ..resources import Resource, ResourceType, normalized_document
from .detect import find_secrets
from .safeload import load_json

ADMIN_PORTS = (22, 3389, 5985, 5986)
DATABASE_PORTS = (1433, 1521, 3306, 5432, 6379, 9200, 27017)
UNRESTRICTED_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "on", "1", "enabled"}
    return bool(value)


def _ingress(address: str, after: Mapping, provider: str, *, ports, cidrs, protocol="tcp", index=0) -> Resource:
    return Resource(
        resource_type=ResourceType.INGRESS_RULE,
        resource_id=f"{address}#ingress{index}",
        provider=provider,
        name=str(after.get("name") or address),
        source_path=address,
        attributes={
            "ports": sorted({int(port) for port in ports}),
            "protocol": protocol,
            "source_cidrs": sorted(set(cidrs)),
            "direction": "ingress",
        },
    )


def _aws_security_group(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    for index, block in enumerate(_as_list(after.get("ingress"))):
        if not isinstance(block, Mapping):
            continue
        from_port = int(block.get("from_port") or 0)
        to_port = int(block.get("to_port") or from_port)
        ports = range(from_port, min(to_port, from_port + 1024) + 1)
        yield _ingress(
            address,
            after,
            provider,
            ports=ports,
            cidrs=[*_as_list(block.get("cidr_blocks")), *_as_list(block.get("ipv6_cidr_blocks"))],
            protocol=str(block.get("protocol") or "tcp"),
            index=index,
        )


def _aws_security_group_rule(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    if str(after.get("type", "ingress")) != "ingress":
        return
    from_port = int(after.get("from_port") or 0)
    to_port = int(after.get("to_port") or from_port)
    yield _ingress(
        address,
        after,
        provider,
        ports=range(from_port, min(to_port, from_port + 1024) + 1),
        cidrs=[*_as_list(after.get("cidr_blocks")), *_as_list(after.get("ipv6_cidr_blocks"))],
        protocol=str(after.get("protocol") or "tcp"),
    )


def _azure_network_security_rule(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    if str(after.get("direction", "Inbound")).lower() != "inbound":
        return
    if str(after.get("access", "Allow")).lower() != "allow":
        return
    prefixes = [*_as_list(after.get("source_address_prefix")), *_as_list(after.get("source_address_prefixes"))]
    cidrs = ["0.0.0.0/0" if str(item) in {"*", "Internet", "Any"} else str(item) for item in prefixes]
    ports = []
    for entry in [*_as_list(after.get("destination_port_range")), *_as_list(after.get("destination_port_ranges"))]:
        text = str(entry)
        if text == "*":
            ports.extend([*ADMIN_PORTS, *DATABASE_PORTS])
        elif "-" in text:
            start, _, end = text.partition("-")
            if start.isdigit() and end.isdigit():
                ports.extend(range(int(start), min(int(end), int(start) + 1024) + 1))
        elif text.isdigit():
            ports.append(int(text))
    yield _ingress(address, after, provider, ports=ports, cidrs=cidrs, protocol=str(after.get("protocol") or "tcp"))


def _gcp_firewall(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    if str(after.get("direction", "INGRESS")).upper() != "INGRESS":
        return
    ports: list[int] = []
    protocol = "tcp"
    for allow in _as_list(after.get("allow")):
        if not isinstance(allow, Mapping):
            continue
        protocol = str(allow.get("protocol") or protocol)
        for entry in _as_list(allow.get("ports")):
            text = str(entry)
            if "-" in text:
                start, _, end = text.partition("-")
                if start.isdigit() and end.isdigit():
                    ports.extend(range(int(start), min(int(end), int(start) + 1024) + 1))
            elif text.isdigit():
                ports.append(int(text))
        if not allow.get("ports"):
            ports.extend([*ADMIN_PORTS, *DATABASE_PORTS])
    yield _ingress(address, after, provider, ports=ports, cidrs=_as_list(after.get("source_ranges")), protocol=protocol)


def _aws_s3_bucket(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    yield Resource(
        resource_type=ResourceType.STORAGE_BUCKET,
        resource_id=address,
        provider=provider,
        name=str(after.get("bucket") or after.get("name") or address),
        source_path=address,
        attributes={
            "public_access_blocked": _truthy(after.get("block_public_access", True)),
            "acl": str(after.get("acl") or "private"),
            "encrypted": bool(after.get("server_side_encryption_configuration")),
            "versioning_enabled": _truthy(
                (after.get("versioning") or [{}])[0].get("enabled")
                if isinstance(after.get("versioning"), list) and after.get("versioning")
                else after.get("versioning")
            ),
            "holds_sensitive_data": True,
        },
    )


def _azure_storage_account(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    yield Resource(
        resource_type=ResourceType.STORAGE_BUCKET,
        resource_id=address,
        provider=provider,
        name=str(after.get("name") or address),
        source_path=address,
        attributes={
            "public_access_blocked": not _truthy(after.get("allow_nested_items_to_be_public")),
            "acl": "private" if not _truthy(after.get("allow_nested_items_to_be_public")) else "public",
            "encrypted": True,
            "min_tls_version": str(after.get("min_tls_version") or ""),
            "https_only": _truthy(after.get("enable_https_traffic_only", True)),
            "holds_sensitive_data": True,
        },
    )


def _gcp_storage_bucket(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    uniform = after.get("uniform_bucket_level_access")
    yield Resource(
        resource_type=ResourceType.STORAGE_BUCKET,
        resource_id=address,
        provider=provider,
        name=str(after.get("name") or address),
        source_path=address,
        attributes={
            "public_access_blocked": _truthy(after.get("public_access_prevention") == "enforced") or _truthy(uniform),
            "acl": "private",
            "encrypted": True,
            "versioning_enabled": _truthy(after.get("versioning")),
            "holds_sensitive_data": True,
        },
    )


def _aws_instance(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    root = _as_list(after.get("root_block_device"))
    metadata_options = _as_list(after.get("metadata_options"))
    yield Resource(
        resource_type=ResourceType.COMPUTE_INSTANCE,
        resource_id=address,
        provider=provider,
        name=str((after.get("tags") or {}).get("Name") or address),
        source_path=address,
        labels={str(k): str(v) for k, v in (after.get("tags") or {}).items()},
        attributes={
            "public_ip_assigned": _truthy(after.get("associate_public_ip_address")),
            "image": str(after.get("ami") or ""),
            "root_volume_encrypted": _truthy(root[0].get("encrypted")) if root else False,
            "imds_v2_required": (
                str(metadata_options[0].get("http_tokens", "")).lower() == "required" if metadata_options else False
            ),
        },
    )


def _aws_db_instance(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    yield Resource(
        resource_type=ResourceType.DATABASE_INSTANCE,
        resource_id=address,
        provider=provider,
        name=str(after.get("identifier") or address),
        source_path=address,
        attributes={
            "encrypted": _truthy(after.get("storage_encrypted")),
            "publicly_accessible": _truthy(after.get("publicly_accessible")),
            "backup_retention_days": int(after.get("backup_retention_period") or 0),
            "engine": str(after.get("engine") or ""),
            "holds_sensitive_data": True,
        },
    )


def _aws_ebs_volume(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    yield Resource(
        resource_type=ResourceType.STORAGE_VOLUME,
        resource_id=address,
        provider=provider,
        name=str(after.get("name") or address),
        source_path=address,
        attributes={"encrypted": _truthy(after.get("encrypted")), "holds_sensitive_data": True},
    )


def _iam_policy(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    document = after.get("policy")
    statements: list[Mapping] = []
    if isinstance(document, Mapping):
        statements = [item for item in _as_list(document.get("Statement")) if isinstance(item, Mapping)]
    wildcard_action = any(
        "*" in _as_list(statement.get("Action")) and str(statement.get("Effect", "Allow")).lower() == "allow"
        for statement in statements
    )
    wildcard_resource = any(
        "*" in _as_list(statement.get("Resource")) and str(statement.get("Effect", "Allow")).lower() == "allow"
        for statement in statements
    )
    yield Resource(
        resource_type=ResourceType.IDENTITY_POLICY,
        resource_id=address,
        provider=provider,
        name=str(after.get("name") or address),
        source_path=address,
        attributes={
            "wildcard_actions": wildcard_action,
            "wildcard_resources": wildcard_resource,
            # A policy document supplied as an opaque string cannot be judged
            # here; the rule reports manual review rather than assuming safety.
            "document_parsed": isinstance(document, Mapping),
        },
    )


def _logging_sink(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    yield Resource(
        resource_type=ResourceType.LOGGING_SINK,
        resource_id=address,
        provider=provider,
        name=str(after.get("name") or address),
        source_path=address,
        attributes={
            "enabled": _truthy(after.get("enable_logging", after.get("enabled", True))),
            "centralized": bool(after.get("s3_bucket_name") or after.get("destination") or after.get("bucket")),
            "retention_days": int(after.get("retention_in_days") or after.get("retention_days") or 0),
            "captures_admin_activity": True,
        },
    )


def _backup_plan(address: str, after: Mapping, provider: str) -> Iterator[Resource]:
    retention = 0
    for rule in _as_list(after.get("rule")):
        if isinstance(rule, Mapping):
            for lifecycle in _as_list(rule.get("lifecycle")):
                if isinstance(lifecycle, Mapping):
                    retention = max(retention, int(lifecycle.get("delete_after") or 0))
    yield Resource(
        resource_type=ResourceType.BACKUP_PLAN,
        resource_id=address,
        provider=provider,
        name=str(after.get("name") or address),
        source_path=address,
        attributes={"retention_days": retention},
    )


# Terraform resource type -> adapter. Unlisted types are reported as unmapped.
ADAPTERS = {
    "aws_security_group": _aws_security_group,
    "aws_security_group_rule": _aws_security_group_rule,
    "aws_vpc_security_group_ingress_rule": _aws_security_group_rule,
    "azurerm_network_security_rule": _azure_network_security_rule,
    "google_compute_firewall": _gcp_firewall,
    "aws_s3_bucket": _aws_s3_bucket,
    "azurerm_storage_account": _azure_storage_account,
    "google_storage_bucket": _gcp_storage_bucket,
    "aws_instance": _aws_instance,
    "aws_db_instance": _aws_db_instance,
    "aws_rds_cluster": _aws_db_instance,
    "aws_ebs_volume": _aws_ebs_volume,
    "aws_iam_policy": _iam_policy,
    "aws_iam_role_policy": _iam_policy,
    "aws_cloudtrail": _logging_sink,
    "aws_cloudwatch_log_group": _logging_sink,
    "google_logging_project_sink": _logging_sink,
    "aws_backup_plan": _backup_plan,
}

PROVIDER_PREFIX = {"aws": "aws", "azurerm": "azure", "azuread": "azure", "google": "gcp", "kubernetes": "kubernetes"}


def _infer_provider(terraform_type: str, default: str) -> str:
    prefix = terraform_type.split("_", 1)[0]
    return PROVIDER_PREFIX.get(prefix, default)


def _iter_planned(module: Mapping) -> Iterator[Mapping]:
    for resource in module.get("resources") or ():
        if isinstance(resource, Mapping):
            yield resource
    for child in module.get("child_modules") or ():
        if isinstance(child, Mapping):
            yield from _iter_planned(child)


def _iter_changes(document: Mapping) -> Iterator[tuple[str, str, Mapping]]:
    """Yield ``(address, terraform_type, resolved_attributes)`` for each resource.

    ``resource_changes`` wins when present because it distinguishes creates and
    updates from deletions; a resource being destroyed should not be assessed.
    """
    changes = document.get("resource_changes")
    if isinstance(changes, list) and changes:
        for entry in changes:
            if not isinstance(entry, Mapping):
                continue
            change = entry.get("change")
            if not isinstance(change, Mapping):
                continue
            actions = {str(action) for action in change.get("actions") or ()}
            if actions <= {"delete", "no-op"}:
                continue
            after = change.get("after")
            if isinstance(after, Mapping):
                yield str(entry.get("address") or ""), str(entry.get("type") or ""), after
        return
    planned = document.get("planned_values")
    root = planned.get("root_module") if isinstance(planned, Mapping) else None
    if isinstance(root, Mapping):
        for resource in _iter_planned(root):
            values = resource.get("values")
            if isinstance(values, Mapping):
                yield str(resource.get("address") or ""), str(resource.get("type") or ""), values


def normalize(payload: bytes, *, provider: str = "aws") -> dict:
    document = load_json(payload)
    if not isinstance(document, Mapping):
        raise UnsafeArtifact("A Terraform plan must be a JSON object.")
    if "resource_changes" not in document and "planned_values" not in document:
        raise UnsafeArtifact("Artifact is not a Terraform plan: no resource_changes or planned_values.")

    resources: list[Resource] = []
    unmapped: dict[str, int] = {}
    mapped_count = 0
    for address, terraform_type, after in _iter_changes(document):
        if not address or not terraform_type:
            continue
        resource_provider = _infer_provider(terraform_type, provider)
        adapter = ADAPTERS.get(terraform_type)
        if adapter is None:
            unmapped[terraform_type] = unmapped.get(terraform_type, 0) + 1
        else:
            resources.extend(adapter(address, after, resource_provider))
            mapped_count += 1
        resources.extend(find_secrets(after, source_path=address, owner_id=address, provider=resource_provider))

    return normalized_document(
        provider=provider,
        source_type="terraform_plan",
        resources=resources,
        metadata={
            "terraform_version": str(document.get("terraform_version") or ""),
            "format_version": str(document.get("format_version") or ""),
            "mapped_resources": mapped_count,
            "unmapped_types": dict(sorted(unmapped.items())),
            "normalizer": "terraform",
        },
    )
