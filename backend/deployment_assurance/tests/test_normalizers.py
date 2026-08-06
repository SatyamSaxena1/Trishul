"""Normalizer behaviour and artifact-safety bounds."""

import json

import pytest

from deployment_assurance.limits import ArtifactTooLarge, UnsafeArtifact
from deployment_assurance.normalizers import compose, inventory, kubernetes, normalize, terraform
from deployment_assurance.normalizers.detect import find_secrets
from deployment_assurance.normalizers.safeload import load_json, load_yaml_documents
from deployment_assurance.resources import ResourceType, canonical_json

from .conftest import terraform_plan


def resources_of(document, resource_type):
    return [item for item in document["resources"] if item["resource_type"] == resource_type]


def test_terraform_maps_open_admin_port_and_records_unmapped_types():
    payload = terraform_plan(
        (
            "aws_security_group.bastion",
            "aws_security_group",
            {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
        ),
        ("aws_lambda_function.unknown", "aws_lambda_function", {"function_name": "worker"}),
    )
    document = terraform.normalize(payload)
    ingress = resources_of(document, ResourceType.INGRESS_RULE)
    assert len(ingress) == 1
    assert ingress[0]["attributes"]["ports"] == [22]
    assert ingress[0]["attributes"]["source_cidrs"] == ["0.0.0.0/0"]
    # An unrecognised type must be surfaced, never silently dropped.
    assert document["metadata"]["unmapped_types"] == {"aws_lambda_function": 1}


def test_terraform_skips_resources_scheduled_for_deletion():
    payload = json.dumps(
        {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.retired",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["delete"], "after": None},
                }
            ],
        }
    ).encode()
    assert terraform.normalize(payload)["resources"] == []


def test_terraform_falls_back_to_planned_values():
    payload = json.dumps(
        {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_db_instance.main",
                            "type": "aws_db_instance",
                            "values": {"storage_encrypted": False, "publicly_accessible": True},
                        }
                    ]
                }
            },
        }
    ).encode()
    databases = resources_of(terraform.normalize(payload), ResourceType.DATABASE_INSTANCE)
    assert databases[0]["attributes"]["publicly_accessible"] is True


def test_terraform_rejects_non_plan_json():
    with pytest.raises(UnsafeArtifact):
        terraform.normalize(b'{"hello": "world"}')


def test_kubernetes_resolves_container_over_pod_security_context():
    manifest = b"""
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 1000}
      hostNetwork: true
      containers:
        - name: api
          image: registry.example/api:1.2.3
          securityContext: {privileged: true, runAsUser: 0}
"""
    containers = resources_of(kubernetes.normalize(manifest), ResourceType.CONTAINER)
    assert len(containers) == 1
    attributes = containers[0]["attributes"]
    # Container-level runAsUser: 0 must win over the pod-level non-root setting.
    assert attributes["privileged"] is True
    assert attributes["runs_as_root"] is True
    assert attributes["host_network"] is True
    assert attributes["image_digest_pinned"] is False


def test_kubernetes_unwraps_cronjob_pod_template():
    manifest = b"""
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly, namespace: ops}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: registry.example/job@sha256:abc
"""
    containers = resources_of(kubernetes.normalize(manifest), ResourceType.CONTAINER)
    assert containers[0]["resource_id"] == "ops/CronJob/nightly/job"
    assert containers[0]["attributes"]["image_digest_pinned"] is True


def test_kubernetes_rejects_documents_without_kind():
    with pytest.raises(UnsafeArtifact):
        kubernetes.normalize(b"just: a mapping\n")


def test_compose_distinguishes_loopback_from_public_publishing():
    document = compose.normalize(
        b"""
services:
  public:
    image: nginx:1.27
    ports: ["8080:80"]
  private:
    image: nginx:1.27
    ports: ["127.0.0.1:9090:90"]
"""
    )
    ingress = {item["resource_id"]: item["attributes"] for item in resources_of(document, ResourceType.INGRESS_RULE)}
    assert ingress["compose/public#ports"]["source_cidrs"] == ["0.0.0.0/0"]
    assert ingress["compose/private#ports"]["source_cidrs"] == []
    assert ingress["compose/private#ports"]["loopback_only"] is True


def test_compose_detects_plaintext_environment_secret_without_storing_it():
    secret_value = "S3cretP@ssw0rd-not-a-reference"
    document = compose.normalize(
        f"""
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: {secret_value}
      REFERENCED_TOKEN: ${{VAULT_TOKEN}}
""".encode()
    )
    secrets = resources_of(document, ResourceType.SECRET_MATERIAL)
    assert len(secrets) == 1, "a ${...} reference must not be reported as material"
    serialized = canonical_json(document).decode()
    assert secret_value not in serialized, "the secret value must never reach the evidence document"
    assert len(secrets[0]["attributes"]["value_sha256"]) == 64


def test_inventory_rejects_unknown_canonical_resource_type():
    payload = json.dumps(
        {
            "schema_version": "trishul-inventory/1.0",
            "provider": "on_prem",
            "resources": [{"resource_type": "made.up", "resource_id": "x"}],
        }
    ).encode()
    with pytest.raises(UnsafeArtifact):
        inventory.normalize(payload)


def test_inventory_maps_hosts_and_vulnerabilities():
    payload = json.dumps(
        {
            "schema_version": "trishul-inventory/1.0",
            "provider": "on_prem",
            "hosts": [{"host_id": "web-01", "os_name": "Ubuntu", "os_version": "18.04"}],
            "vulnerabilities": [{"id": "V1", "cve": "CVE-2024-1", "cvss": 9.8, "asset_id": "web-01"}],
        }
    ).encode()
    document = inventory.normalize(payload)
    assert resources_of(document, ResourceType.OS_HOST)[0]["attributes"]["os_name"] == "ubuntu"
    assert resources_of(document, ResourceType.VULNERABILITY)[0]["attributes"]["cvss"] == 9.8


def test_cloud_inventory_retains_its_source_type():
    payload = json.dumps({"schema_version": "trishul-inventory/1.0", "provider": "aws", "resources": []}).encode()
    assert normalize(source_type="cloud_inventory", payload=payload, provider="aws")["source_type"] == "cloud_inventory"


def test_yaml_aliases_are_refused():
    """Alias expansion is the billion-laughs vector and must not be parsed."""
    bomb = b"""
a: &anchor ["x", "x", "x"]
b: *anchor
"""
    with pytest.raises(UnsafeArtifact):
        list(load_yaml_documents(bomb))


def test_oversized_artifact_is_refused_before_parsing():
    with pytest.raises(ArtifactTooLarge):
        load_json(b"[" + b"0," * 20_000_000 + b"0]")


def test_deeply_nested_json_is_refused():
    with pytest.raises(UnsafeArtifact):
        load_json(b"[" * 200 + b"]" * 200)


def test_normalization_is_order_independent():
    """Two plans differing only in resource order must hash identically."""
    first = terraform_plan(
        ("aws_s3_bucket.a", "aws_s3_bucket", {"bucket": "a"}),
        ("aws_s3_bucket.b", "aws_s3_bucket", {"bucket": "b"}),
    )
    second = terraform_plan(
        ("aws_s3_bucket.b", "aws_s3_bucket", {"bucket": "b"}),
        ("aws_s3_bucket.a", "aws_s3_bucket", {"bucket": "a"}),
    )
    assert canonical_json(terraform.normalize(first)) == canonical_json(terraform.normalize(second))


def test_secret_detector_ignores_placeholders_and_short_values():
    assert find_secrets({"password": "changeme"}, source_path="p", owner_id="o") == []
    assert find_secrets({"password": "short"}, source_path="p", owner_id="o") == []
    assert find_secrets({"api_key": "/run/secrets/api_key"}, source_path="p", owner_id="o") == []
    assert len(find_secrets({"api_key": "AKIAIOSFODNN7EXAMPLE"}, source_path="p", owner_id="o")) == 1
