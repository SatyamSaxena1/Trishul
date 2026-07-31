import httpx
import pytest
from django.utils import timezone
from jsonschema import ValidationError as JSONSchemaError

from core.ai_gateway import GatewayPolicyError
from core.models import (
    Application,
    Finding,
    ModelConfiguration,
    Organization,
    PromptVersion,
    Repository,
    RepositoryVersion,
    Scan,
    Tenant,
    Workspace,
)
from core.tasks import enrich_scan, execute_scan
from core.tenancy import tenant_context


def make_scan():
    tenant = Tenant.objects.create(slug="scan-tenant", name="Scan tenant")
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name="Org")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name="Workspace")
        application = Application.objects.create(tenant=tenant, workspace=workspace, name="App")
        repository = Repository.objects.create(tenant=tenant, application=application, name="Repo")
        version = RepositoryVersion.objects.create(
            tenant=tenant,
            repository=repository,
            object_key="archive",
            sha256="a" * 64,
            size=1,
            manifest={"files": 1},
        )
        scan = Scan.objects.create(
            tenant=tenant,
            repository_version=version,
            language_pack="python-stdlib",
            language_pack_version="1.0",
            coverage={"pending": True},
        )
    return tenant, scan


RESULT = {
    "findings": [
        {
            "rule_id": "PY001",
            "rule_version": "1",
            "title": "Finding",
            "description": "Deterministic",
            "cwe": "CWE-1",
            "asvs": "",
            "severity": 4,
            "confidence": 5,
            "status": "confirmed",
            "remediation": "Deterministic fix",
            "fingerprint": "b" * 64,
            "file_path": "app.py",
            "start_line": 1,
            "end_line": 1,
            "snippet_hash": "c" * 64,
        }
    ],
    "coverage": {"files": 1},
    "pack": "python-stdlib",
    "pack_version": "1.0",
}


@pytest.mark.django_db(transaction=True)
def test_deterministic_scan_commits_before_optional_ai(monkeypatch):
    tenant, scan = make_scan()
    monkeypatch.setattr("core.tasks.analyze", lambda **kwargs: RESULT)
    monkeypatch.setattr("core.tasks.enrich_scan.apply_async", lambda **kwargs: (_ for _ in ()).throw(RuntimeError()))

    execute_scan(str(tenant.id), str(scan.id))

    scan.refresh_from_db()
    finding = Finding.all_objects.get(scan=scan)
    assert scan.state == Scan.State.COMPLETED
    assert finding.status == Finding.Status.CONFIRMED
    assert finding.severity == 4
    assert finding.ai_advisory == {}


def configure_ai(tenant):
    with tenant_context(tenant.id):
        configuration = ModelConfiguration.objects.create(
            tenant=tenant,
            name="AI",
            endpoint_type="private_http",
            endpoint_url="https://model.internal",
            model_name="model",
            credential_reference="missing",
            allowed_data_classes=["source"],
            timeout_seconds=1,
        )
        prompt = PromptVersion.objects.create(
            tenant=tenant,
            workflow="scan_enrichment",
            version_name="1",
            template_hash="d" * 64,
            approved_at=timezone.now(),
        )
    return configuration, prompt


@pytest.mark.django_db
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(None, id="absent-credentials"),
        pytest.param(GatewayPolicyError("denied allowlist"), id="denied-allowlist"),
        pytest.param(httpx.ReadTimeout("timeout"), id="timeout"),
        pytest.param(JSONSchemaError("malformed schema output"), id="malformed-schema"),
        pytest.param(httpx.ConnectError("endpoint failure"), id="endpoint-failure"),
    ],
)
def test_optional_ai_failures_do_not_change_deterministic_finding(monkeypatch, failure):
    tenant, scan = make_scan()
    with tenant_context(tenant.id):
        finding = Finding.objects.create(
            tenant=tenant,
            scan=scan,
            rule_id="PY001",
            rule_version="1",
            language="python",
            title="Finding",
            description="Deterministic",
            severity=4,
            confidence=5,
            status="confirmed",
            remediation="Fixed rule",
            fingerprint="e" * 64,
        )
    configure_ai(tenant)
    if failure is None:
        # Exercise the gateway's absent credential behavior while avoiding DNS/network access.
        monkeypatch.setattr("core.ai_gateway.validate_endpoint", lambda url: None)
    else:
        monkeypatch.setattr("core.tasks.invoke", lambda **kwargs: (_ for _ in ()).throw(failure))

    result = enrich_scan(str(tenant.id), str(scan.id))

    finding.refresh_from_db()
    assert result["state"] == "failed"
    assert (finding.status, finding.severity, finding.remediation) == ("confirmed", 4, "Fixed rule")
    assert finding.ai_advisory == {}
