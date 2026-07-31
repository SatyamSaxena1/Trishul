import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


def backfill_finding_provenance(apps, schema_editor):
    Finding = apps.get_model("core", "Finding")
    FindingEvidence = apps.get_model("core", "FindingEvidence")
    for finding in Finding.objects.select_related("scan").iterator():
        evidence = FindingEvidence.objects.filter(finding_id=finding.id).order_by("created_at").first()
        finding.repository_version_id = finding.scan.repository_version_id
        finding.analyzer_name = finding.scan.language_pack
        finding.analyzer_version = finding.scan.language_pack_version
        finding.file_path = evidence.file_path if evidence else "unknown"
        finding.start_line = evidence.start_line if evidence else 1
        finding.end_line = evidence.end_line if evidence else 1
        finding.evidence = {
            "snippet_sha256": evidence.snippet_hash if evidence else finding.fingerprint,
            "legacy_evidence_id": str(evidence.id) if evidence else None,
        }
        finding.decision_at = finding.created_at
        finding.save(update_fields=[
            "repository_version", "analyzer_name", "analyzer_version", "file_path",
            "start_line", "end_line", "evidence", "decision_at",
        ])


class Migration(migrations.Migration):
    dependencies = [("core", "0004_job_application")]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="analyst_decision",
            field=models.CharField(
                choices=[
                    ("accepted", "Accepted"),
                    ("false_positive", "False positive"),
                    ("duplicate", "Duplicate"),
                    ("needs_context", "Needs context"),
                ],
                default="needs_context",
                max_length=30,
            ),
        ),
        migrations.AddField(model_name="finding", name="analyzer_image_digest", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="finding", name="analyzer_name", field=models.CharField(max_length=160, null=True)),
        migrations.AddField(model_name="finding", name="analyzer_version", field=models.CharField(max_length=80, null=True)),
        migrations.AddField(model_name="finding", name="decision_at", field=models.DateTimeField(null=True)),
        migrations.AddField(model_name="finding", name="end_line", field=models.PositiveIntegerField(null=True)),
        migrations.AddField(model_name="finding", name="evidence", field=models.JSONField(null=True)),
        migrations.AddField(model_name="finding", name="file_path", field=models.CharField(max_length=600, null=True)),
        migrations.AddField(
            model_name="finding",
            name="repository_version",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, to="core.repositoryversion"),
        ),
        migrations.AddField(model_name="finding", name="start_line", field=models.PositiveIntegerField(null=True)),
        migrations.AlterField(
            model_name="findingevidence",
            name="finding",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="evidence_records", to="core.finding"),
        ),
        migrations.RunPython(backfill_finding_provenance, migrations.RunPython.noop),
        migrations.AlterField(model_name="finding", name="analyzer_name", field=models.CharField(max_length=160)),
        migrations.AlterField(model_name="finding", name="analyzer_version", field=models.CharField(max_length=80)),
        migrations.AlterField(model_name="finding", name="decision_at", field=models.DateTimeField(default=django.utils.timezone.now)),
        migrations.AlterField(model_name="finding", name="end_line", field=models.PositiveIntegerField()),
        migrations.AlterField(model_name="finding", name="evidence", field=models.JSONField()),
        migrations.AlterField(model_name="finding", name="file_path", field=models.CharField(max_length=600)),
        migrations.AlterField(
            model_name="finding",
            name="repository_version",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="core.repositoryversion"),
        ),
        migrations.AlterField(model_name="finding", name="start_line", field=models.PositiveIntegerField()),
    ]
