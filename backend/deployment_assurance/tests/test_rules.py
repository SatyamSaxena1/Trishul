"""Rule behaviour: positive, negative, not-applicable and unknown-input cases.

Every blocking rule needs all four. A rule that only has a failing fixture is a
rule that will eventually block a legitimate deployment, and a rule with no
unknown-input fixture is a rule that will silently pass incomplete evidence.
"""

import pytest

from deployment_assurance.policy import REGISTRY
from deployment_assurance.policy.packs import baseline
from deployment_assurance.policy.sdk import (
    FAIL,
    MANUAL_REVIEW,
    NOT_APPLICABLE,
    PASS,
    WARNING,
    RuleContext,
    TargetFacts,
    result_fingerprint,
)
from deployment_assurance.resources import Resource, ResourceType

PRODUCTION = TargetFacts(
    environment="production",
    provider="aws",
    criticality=5,
    data_sensitivity=5,
    internet_exposed=True,
    is_production=True,
)
DEVELOPMENT = TargetFacts(
    environment="development",
    provider="aws",
    criticality=2,
    data_sensitivity=2,
    internet_exposed=False,
    is_production=False,
)


def context(target=PRODUCTION, rule=None, **parameters):
    merged = dict(rule.default_parameters) if rule else {}
    merged.update(parameters)
    return RuleContext(target=target, parameters=merged, policy_version="test")


def outcomes(rule, resource, target=PRODUCTION, **parameters):
    return [result.outcome for result in rule.evaluate(context(target, rule, **parameters), resource)]


def ingress(**attributes):
    return Resource(
        resource_type=ResourceType.INGRESS_RULE,
        resource_id="sg-1",
        attributes={"ports": [], "source_cidrs": [], **attributes},
    )


def container(**attributes):
    defaults = {
        "image": "registry.example/app:1.0",
        "image_digest_pinned": False,
        "privileged": False,
        "allow_privilege_escalation": False,
        "read_only_root_filesystem": True,
        "runs_as_root": False,
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "host_path_mounts": [],
        "added_capabilities": [],
        "has_resource_limits": True,
    }
    return Resource(
        resource_type=ResourceType.CONTAINER,
        resource_id="ns/Deployment/app/c",
        attributes={**defaults, **attributes},
    )


# --- DA-NET-001 -----------------------------------------------------------


def test_public_admin_port_fails_when_unrestricted():
    rule = baseline.PublicAdminPort()
    assert outcomes(rule, ingress(ports=[22], source_cidrs=["0.0.0.0/0"])) == [FAIL]


def test_public_admin_port_passes_when_restricted():
    rule = baseline.PublicAdminPort()
    assert outcomes(rule, ingress(ports=[22], source_cidrs=["10.0.0.0/8"])) == [PASS]


def test_public_admin_port_not_applicable_for_other_ports():
    rule = baseline.PublicAdminPort()
    assert outcomes(rule, ingress(ports=[443], source_cidrs=["0.0.0.0/0"])) == [NOT_APPLICABLE]


def test_public_admin_port_ignores_unrelated_resource_types():
    rule = baseline.PublicAdminPort()
    assert rule.evaluate(context(rule=rule), container()) == ()


def test_public_admin_port_honours_ipv6_wildcard():
    rule = baseline.PublicAdminPort()
    assert outcomes(rule, ingress(ports=[3389], source_cidrs=["::/0"])) == [FAIL]


# --- DA-NET-002 -----------------------------------------------------------


def test_public_database_instance_fails():
    rule = baseline.PublicDatabasePort()
    resource = Resource(
        resource_type=ResourceType.DATABASE_INSTANCE,
        resource_id="db-1",
        attributes={"publicly_accessible": True},
    )
    assert outcomes(rule, resource) == [FAIL]


def test_private_database_instance_passes():
    rule = baseline.PublicDatabasePort()
    resource = Resource(
        resource_type=ResourceType.DATABASE_INSTANCE,
        resource_id="db-1",
        attributes={"publicly_accessible": False},
    )
    assert outcomes(rule, resource) == [PASS]


# --- DA-ENC-001 -----------------------------------------------------------


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        ({"encrypted": True}, PASS),
        ({"encrypted": False}, FAIL),
        # Absent information is not evidence of compliance.
        ({}, MANUAL_REVIEW),
        ({"holds_sensitive_data": False}, NOT_APPLICABLE),
    ],
)
def test_encryption_at_rest(attributes, expected):
    rule = baseline.EncryptionAtRest()
    resource = Resource(resource_type=ResourceType.STORAGE_BUCKET, resource_id="b", attributes=attributes)
    assert outcomes(rule, resource) == [expected]


# --- DA-VULN-001 ----------------------------------------------------------


@pytest.mark.parametrize(
    ("cvss", "exploit_known", "expected"),
    [(9.8, False, FAIL), (7.5, True, FAIL), (7.5, False, WARNING), (4.0, False, PASS)],
)
def test_critical_vulnerability(cvss, exploit_known, expected):
    rule = baseline.CriticalVulnerability()
    resource = Resource(
        resource_type=ResourceType.VULNERABILITY,
        resource_id="v",
        attributes={"cve": "CVE-2024-1", "cvss": cvss, "exploit_known": exploit_known},
    )
    assert outcomes(rule, resource) == [expected]


# --- DA-OS-001 ------------------------------------------------------------


@pytest.mark.parametrize(
    ("os_name", "os_version", "expected"),
    [("ubuntu", "22.04", PASS), ("ubuntu", "18.04", FAIL), ("plan9", "4", MANUAL_REVIEW)],
)
def test_unsupported_operating_system(os_name, os_version, expected):
    rule = baseline.UnsupportedOperatingSystem()
    resource = Resource(
        resource_type=ResourceType.OS_HOST,
        resource_id="h",
        attributes={"os_name": os_name, "os_version": os_version},
    )
    assert outcomes(rule, resource) == [expected]


# --- DA-IAM-001 -----------------------------------------------------------


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        ({"wildcard_actions": True, "wildcard_resources": True}, FAIL),
        ({"wildcard_actions": True, "wildcard_resources": False}, WARNING),
        ({"wildcard_actions": False, "wildcard_resources": False}, PASS),
        ({"document_parsed": False}, MANUAL_REVIEW),
    ],
)
def test_wildcard_identity_grant(attributes, expected):
    rule = baseline.WildcardIdentityGrant()
    resource = Resource(resource_type=ResourceType.IDENTITY_POLICY, resource_id="p", attributes=attributes)
    assert outcomes(rule, resource) == [expected]


# --- Container rules ------------------------------------------------------


def test_privileged_container_fails():
    assert outcomes(baseline.PrivilegedContainer(), container(privileged=True)) == [FAIL]


def test_dangerous_capability_fails():
    assert outcomes(baseline.PrivilegedContainer(), container(added_capabilities=["SYS_ADMIN"])) == [FAIL]


def test_ordinary_container_passes_privilege_rule():
    assert outcomes(baseline.PrivilegedContainer(), container()) == [PASS]


def test_host_namespace_sharing_fails():
    assert outcomes(baseline.HostNamespaceAccess(), container(host_pid=True)) == [FAIL]


def test_sensitive_host_path_fails_including_subpaths():
    rule = baseline.HostNamespaceAccess()
    assert outcomes(rule, container(host_path_mounts=["/var/run/docker.sock"])) == [FAIL]
    assert outcomes(rule, container(host_path_mounts=["/etc/ssl/certs"])) == [FAIL]


def test_innocuous_host_path_passes():
    assert outcomes(baseline.HostNamespaceAccess(), container(host_path_mounts=["/opt/app-data"])) == [PASS]


def test_root_container_blocks_in_production_and_warns_elsewhere():
    """Same finding, proportionate consequence."""
    rule = baseline.ContainerRunsAsRoot()
    assert outcomes(rule, container(runs_as_root=True), PRODUCTION) == [FAIL]
    assert outcomes(rule, container(runs_as_root=True), DEVELOPMENT) == [WARNING]


def test_unpinned_image_blocks_in_production_only():
    rule = baseline.UnpinnedImage()
    assert outcomes(rule, container(image_digest_pinned=False), PRODUCTION) == [FAIL]
    assert outcomes(rule, container(image_digest_pinned=False), DEVELOPMENT) == [WARNING]
    assert outcomes(rule, container(image_digest_pinned=True), PRODUCTION) == [PASS]


# --- Registry invariants --------------------------------------------------


def test_every_rule_declares_a_remediation_and_mappings():
    for rule in REGISTRY:
        assert rule.title, f"{rule.rule_id} has no title"
        assert rule.remediation, f"{rule.rule_id} has no remediation guidance"
        assert rule.resource_types, f"{rule.rule_id} declares no resource types"
        if rule.blocking:
            assert rule.mappings, f"blocking rule {rule.rule_id} has no framework traceability"


def test_registry_iteration_is_sorted_and_stable():
    identifiers = [rule.rule_id for rule in REGISTRY]
    assert identifiers == sorted(identifiers)
    assert identifiers == [rule.rule_id for rule in REGISTRY]


def test_pack_content_hash_is_stable_across_instantiations():
    from deployment_assurance.policy.registry import RuleRegistry

    rebuilt = RuleRegistry(
        key=baseline.PACK_KEY,
        version=baseline.PACK_VERSION,
        title=baseline.PACK_TITLE,
        description=baseline.PACK_DESCRIPTION,
        rules=[type(rule)() for rule in REGISTRY],
    )
    assert rebuilt.content_hash() == REGISTRY.content_hash()


def test_duplicate_rule_ids_are_refused():
    from deployment_assurance.policy.registry import RuleRegistry

    with pytest.raises(ValueError, match="Duplicate rule_id"):
        RuleRegistry("k", "1", "t", "d", [baseline.PublicAdminPort(), baseline.PublicAdminPort()])


def test_fingerprint_changes_with_rule_version():
    """A rule-logic change must retire findings written against the old version."""
    common = {
        "rule_id": "DA-NET-001",
        "resource_type": ResourceType.INGRESS_RULE,
        "resource_id": "sg-1",
        "reason_code": "PUBLIC_ADMIN_PORT",
    }
    assert result_fingerprint(rule_version="1.0.0", **common) != result_fingerprint(rule_version="1.1.0", **common)
