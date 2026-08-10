mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["ap-south-1a", "ap-south-1b", "ap-south-1c"]
    }
  }
}

mock_provider "aws" {
  alias = "dr"
}

run "private_cluster_and_workload_identity" {
  command = plan

  variables {
    github_repository              = "example/trishul"
    github_oidc_provider_arn       = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    codeconnections_connection_arn = "arn:aws:codeconnections:ap-south-1:123456789012:connection/00000000-0000-0000-0000-000000000000"
    security_account_id            = "210987654321"
    audit_checkpoint_bucket_name   = "security-audit-checkpoints"
  }

  assert {
    condition     = aws_eks_cluster.main.vpc_config[0].endpoint_public_access == false
    error_message = "The production default must keep the EKS endpoint private."
  }

  assert {
    condition     = length(aws_eks_pod_identity_association.application) == 2
    error_message = "Only the API and worker service accounts receive the application role."
  }

  assert {
    condition     = !contains(keys(aws_eks_pod_identity_association.application), "trishul-analysis-controller")
    error_message = "The analyzer controller must not receive application AWS credentials."
  }

  assert {
    condition     = aws_eks_pod_identity_association.checkpoint_writer.service_account == "trishul-checkpoint-writer"
    error_message = "Only the checkpoint CronJob receives the cross-account writer role."
  }

  assert {
    condition     = length(aws_s3_bucket_replication_configuration.evidence) == 1 && length(aws_db_instance_automated_backups_replication.postgres) == 1
    error_message = "Primary mode must manage evidence and RDS backup replication."
  }

  assert {
    condition     = aws_s3_bucket_replication_configuration.evidence[0].rule[0].destination[0].replication_time[0].time[0].minutes == 15
    error_message = "Evidence replication must retain the 15-minute RTC objective."
  }

  assert {
    condition     = aws_db_instance_automated_backups_replication.postgres[0].retention_period == 14 && aws_cloudwatch_metric_alarm.rds_recovery_point_age[0].threshold == 900
    error_message = "RDS replication must keep 14 days and alarm beyond the 15-minute RPO target."
  }
}

run "recovery_mode_reuses_replicated_data" {
  command = plan

  variables {
    deployment_mode                   = "recovery"
    aws_region                        = "ap-southeast-1"
    dr_region                         = "ap-southeast-1"
    recovery_evidence_bucket_name     = "trishul-pilot-evidence-dr"
    recovery_evidence_kms_key_arn     = "arn:aws:kms:ap-southeast-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    recovery_db_automated_backups_arn = "arn:aws:rds:ap-southeast-1:123456789012:auto-backup:ab-recovery"
    github_repository                 = "example/trishul"
    github_oidc_provider_arn          = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    codeconnections_connection_arn    = "arn:aws:codeconnections:ap-southeast-1:123456789012:connection/00000000-0000-0000-0000-000000000000"
    security_account_id               = "210987654321"
    audit_checkpoint_bucket_name      = "security-audit-checkpoints"
  }

  override_data {
    target = data.aws_s3_bucket.recovery
    values = {
      id  = "trishul-pilot-evidence-dr"
      arn = "arn:aws:s3:::trishul-pilot-evidence-dr"
    }
  }

  override_data {
    target = data.aws_secretsmanager_secret.recovery
    values = {
      arn = "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:trishul-pilot/runtime"
    }
  }

  override_data {
    target = data.aws_iam_role.checkpoint_writer
    values = {
      arn = "arn:aws:iam::123456789012:role/trishul-pilot-checkpoint-writer"
    }
  }

  assert {
    condition     = length(aws_s3_bucket.evidence) == 0 && length(aws_s3_bucket.evidence_replica) == 0
    error_message = "Recovery mode must reuse the replica rather than create evidence buckets."
  }

  assert {
    condition     = length(aws_db_instance_automated_backups_replication.postgres) == 0 && aws_db_instance.postgres.restore_to_point_in_time[0].use_latest_restorable_time == true && aws_db_instance.postgres.restore_to_point_in_time[0].source_db_instance_automated_backups_arn == var.recovery_db_automated_backups_arn
    error_message = "Recovery mode must restore the latest replicated RDS point without managing replication."
  }
}

run "recovery_mode_rejects_the_wrong_region" {
  command = plan

  variables {
    deployment_mode                   = "recovery"
    aws_region                        = "ap-southeast-2"
    dr_region                         = "ap-southeast-1"
    recovery_evidence_bucket_name     = "trishul-pilot-evidence-dr"
    recovery_evidence_kms_key_arn     = "arn:aws:kms:ap-southeast-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    recovery_db_automated_backups_arn = "arn:aws:rds:ap-southeast-1:123456789012:auto-backup:ab-recovery"
    github_repository                 = "example/trishul"
    github_oidc_provider_arn          = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    codeconnections_connection_arn    = "arn:aws:codeconnections:ap-southeast-2:123456789012:connection/00000000-0000-0000-0000-000000000000"
    security_account_id               = "210987654321"
    audit_checkpoint_bucket_name      = "security-audit-checkpoints"
  }

  override_data {
    target = data.aws_iam_role.checkpoint_writer
    values = {
      arn = "arn:aws:iam::123456789012:role/trishul-pilot-checkpoint-writer"
    }
  }

  expect_failures = [check.recovery_inputs]
}
