import json
from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from core.models import (
    Application,
    AuditEvent,
    Finding,
    FindingReview,
    Job,
    Organization,
    Repository,
    RepositoryVersion,
    Scan,
    Tenant,
    Workspace,
)
from core.tenancy import tenant_context


def make_data(tenant, name, job_state=Job.State.COMPLETED):
    with tenant_context(tenant.id):
        organization = Organization.objects.create(tenant=tenant, name=f"{name} org")
        workspace = Workspace.objects.create(tenant=tenant, organization=organization, name=f"{name} ws")
        application = Application.objects.create(tenant=tenant, workspace=workspace, name=name)
        repository = Repository.objects.create(tenant=tenant, application=application, name=f"secret/{name}")
        version = RepositoryVersion.objects.create(
            tenant=tenant,
            repository=repository,
            object_key="secret/source.tar",
            sha256="a" * 64,
            size=1,
            manifest={"files": 1},
        )
        scan = Scan.objects.create(
            tenant=tenant,
            repository_version=version,
            state=Scan.State.COMPLETED,
            language_pack="python",
            language_pack_version="1",
            coverage={"files": 1},
        )
        finding = Finding.objects.create(
            tenant=tenant,
            scan=scan,
            rule_id="python.safe-rule",
            rule_version="1",
            language="python",
            title="secret title",
            description="raw evidence",
            severity=3,
            confidence=4,
            fingerprint="b" * 64,
        )
        FindingReview.objects.create(
            tenant=tenant,
            finding=finding,
            outcome=FindingReview.Outcome.ACCEPTED,
            useful=True,
            feedback="private reviewer words",
            unresolved_blocker=True,
        )
        Job.objects.create(
            tenant=tenant, application=application, kind="scan", state=job_state, attempts=2, payload={"scan": True}
        )
        AuditEvent.append(
            tenant=tenant,
            actor_type="user",
            actor_id="identifying-user",
            action="drill.restore",
            resource_type="backup",
            resource_id="secret-path",
            details={"result": "passed", "raw": "do not export"},
        )


@pytest.mark.django_db
def test_report_is_tenant_scoped_and_aggregate_only(capsys):
    first = Tenant.objects.create(slug="first", name="First")
    second = Tenant.objects.create(slug="second", name="Second")
    make_data(first, "first")
    make_data(second, "second", Job.State.FAILED)
    now = timezone.now()

    call_command(
        "generate_tenant_report",
        tenant=str(first.id),
        since=(now - timedelta(days=1)).isoformat(),
        until=(now + timedelta(days=1)).isoformat(),
    )
    output = capsys.readouterr().out
    report = json.loads(output)

    assert report["repositories"] == {"submitted": 1, "successfully_analyzed": 1}
    assert report["jobs"]["terminal_outcomes"] == {"completed": 1}
    assert report["findings_by_rule"] == {"python.safe-rule": 1}
    assert report["review_outcomes"]["accepted"] == 1
    assert report["usefulness"]["overall"]["rate"] == 1.0
    assert report["drills"]["restore"]["passed"] == 1
    assert report["reviewer_feedback"] == {
        "note": "Feedback text is intentionally excluded.",
        "reviews_with_feedback": 1,
        "unresolved_blockers": 1,
    }
    forbidden_values = (
        "secret/first",
        "secret/source.tar",
        "raw evidence",
        "private reviewer words",
        "identifying-user",
    )
    for forbidden in forbidden_values:
        assert forbidden not in output
