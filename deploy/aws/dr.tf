resource "aws_kms_key" "dr" {
  provider                = aws.dr
  count                   = local.is_primary ? 1 : 0
  description             = "Trishul ${var.environment} replicated data"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "dr" {
  provider      = aws.dr
  count         = local.is_primary ? 1 : 0
  name          = "alias/${local.name}-replicated-data"
  target_key_id = aws_kms_key.dr[0].key_id
}

resource "aws_s3_bucket" "evidence_replica" {
  provider      = aws.dr
  count         = local.is_primary ? 1 : 0
  bucket_prefix = "${local.name}-evidence-dr-"
}

resource "aws_s3_bucket_public_access_block" "evidence_replica" {
  provider                = aws.dr
  count                   = local.is_primary ? 1 : 0
  bucket                  = aws_s3_bucket.evidence_replica[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence_replica" {
  provider = aws.dr
  count    = local.is_primary ? 1 : 0
  bucket   = aws_s3_bucket.evidence_replica[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_replica" {
  provider = aws.dr
  count    = local.is_primary ? 1 : 0
  bucket   = aws_s3_bucket.evidence_replica[0].id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.dr[0].arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "evidence_replica" {
  provider = aws.dr
  count    = local.is_primary ? 1 : 0
  bucket   = aws_s3_bucket.evidence_replica[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.evidence_replica[0].arn, "${aws_s3_bucket.evidence_replica[0].arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_iam_role" "s3_replication" {
  count = local.is_primary ? 1 : 0
  name  = "${local.name}-evidence-replication"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "s3.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "s3_replication" {
  count = local.is_primary ? 1 : 0
  name  = "cross-region-evidence"
  role  = aws_iam_role.s3_replication[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = aws_s3_bucket.evidence[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
        Resource = "${aws_s3_bucket.evidence[0].arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.data.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
        Resource = "${aws_s3_bucket.evidence_replica[0].arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.dr[0].arn
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.dr_region}.amazonaws.com" }
        }
      },
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "evidence" {
  count  = local.is_primary ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id
  role   = aws_iam_role.s3_replication[0].arn

  rule {
    id     = "evidence-dr"
    status = "Enabled"
    filter {}

    delete_marker_replication { status = "Enabled" }
    source_selection_criteria {
      sse_kms_encrypted_objects { status = "Enabled" }
    }
    destination {
      bucket        = aws_s3_bucket.evidence_replica[0].arn
      storage_class = "STANDARD"
      encryption_configuration { replica_kms_key_id = aws_kms_key.dr[0].arn }
      metrics {
        status = "Enabled"
        event_threshold { minutes = 15 }
      }
      replication_time {
        status = "Enabled"
        time { minutes = 15 }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence, aws_s3_bucket_versioning.evidence_replica]
}

resource "aws_db_instance_automated_backups_replication" "postgres" {
  provider               = aws.dr
  count                  = local.is_primary ? 1 : 0
  source_db_instance_arn = aws_db_instance.postgres.arn
  retention_period       = 14
  kms_key_id             = aws_kms_key.dr[0].arn
}

resource "aws_cloudwatch_metric_alarm" "s3_replication_latency" {
  count               = local.is_primary ? 1 : 0
  alarm_name          = "${local.name}-evidence-replication-latency"
  alarm_description   = "Evidence replication exceeded the 15-minute RTC objective."
  namespace           = "AWS/S3"
  metric_name         = "ReplicationLatency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 900
  statistic           = "Maximum"
  threshold           = 900
  treat_missing_data  = "ignore"
  dimensions = {
    SourceBucket      = aws_s3_bucket.evidence[0].id
    DestinationBucket = aws_s3_bucket.evidence_replica[0].id
    RuleId            = "evidence-dr"
  }
  alarm_actions = [aws_sns_topic.operations.arn]
  ok_actions    = [aws_sns_topic.operations.arn]
}

resource "aws_cloudwatch_metric_alarm" "s3_replication_failures" {
  count               = local.is_primary ? 1 : 0
  alarm_name          = "${local.name}-evidence-replication-failures"
  alarm_description   = "Evidence replication failures, including destination KMS failures."
  namespace           = "AWS/S3"
  metric_name         = "OperationsFailedReplication"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 900
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "ignore"
  dimensions = {
    SourceBucket      = aws_s3_bucket.evidence[0].id
    DestinationBucket = aws_s3_bucket.evidence_replica[0].id
    RuleId            = "evidence-dr"
  }
  alarm_actions = [aws_sns_topic.operations.arn]
  ok_actions    = [aws_sns_topic.operations.arn]
}

resource "aws_sns_topic" "dr_operations" {
  provider          = aws.dr
  count             = local.is_primary ? 1 : 0
  name              = "${local.name}-dr-operations"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "dr_email" {
  provider  = aws.dr
  count     = local.is_primary && var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.dr_operations[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_group" "dr_readiness" {
  provider          = aws.dr
  count             = local.is_primary ? 1 : 0
  name              = "/trishul/${var.environment}/dr-readiness"
  retention_in_days = 30
}

resource "aws_iam_role" "dr_readiness" {
  count = local.is_primary ? 1 : 0
  name  = "${local.name}-dr-readiness"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "codebuild.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "dr_readiness" {
  count = local.is_primary ? 1 : 0
  name  = "measure-recovery-point"
  role  = aws_iam_role.dr_readiness[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["rds:DescribeDBInstanceAutomatedBackups"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "Trishul/DR" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.dr_readiness[0].arn}:*"
      },
    ]
  })
}

resource "aws_codebuild_project" "dr_readiness" {
  provider     = aws.dr
  count        = local.is_primary ? 1 : 0
  name         = "${local.name}-dr-readiness"
  service_role = aws_iam_role.dr_readiness[0].arn

  artifacts { type = "NO_ARTIFACTS" }
  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    environment_variable {
      name  = "BACKUP_ARN"
      value = aws_db_instance_automated_backups_replication.postgres[0].id
    }
    environment_variable {
      name  = "DR_REGION"
      value = var.dr_region
    }
  }
  source {
    type = "NO_SOURCE"
    buildspec = yamlencode({
      version = 0.2
      phases = {
        build = {
          commands = [
            "set -euo pipefail",
            "read -r status latest <<<\"$(aws rds describe-db-instance-automated-backups --region \"$DR_REGION\" --db-instance-automated-backups-arn \"$BACKUP_ARN\" --query 'DBInstanceAutomatedBackups[0].[Status,RestoreWindow.LatestTime]' --output text)\"",
            "latest_epoch=$(date -d \"$latest\" +%s)",
            "age=$(( $(date -u +%s) - latest_epoch ))",
            "if [ \"$status\" = active ]; then healthy=1; else healthy=0; fi",
            "aws cloudwatch put-metric-data --region \"$DR_REGION\" --namespace Trishul/DR --metric-data \"MetricName=RDSBackupRecoveryPointAgeSeconds,Value=$age,Unit=Seconds\" \"MetricName=RDSBackupReplicationHealthy,Value=$healthy,Unit=Count\"",
            "test \"$healthy\" -eq 1",
          ]
        }
      }
    })
  }
  logs_config {
    cloudwatch_logs { group_name = aws_cloudwatch_log_group.dr_readiness[0].name }
  }
}

resource "aws_iam_role" "dr_readiness_events" {
  count = local.is_primary ? 1 : 0
  name  = "${local.name}-dr-readiness-events"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "dr_readiness_events" {
  count = local.is_primary ? 1 : 0
  name  = "start-readiness-check"
  role  = aws_iam_role.dr_readiness_events[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "codebuild:StartBuild", Resource = aws_codebuild_project.dr_readiness[0].arn }]
  })
}

resource "aws_cloudwatch_event_rule" "dr_readiness" {
  provider            = aws.dr
  count               = local.is_primary ? 1 : 0
  name                = "${local.name}-dr-readiness"
  schedule_expression = "rate(15 minutes)"
}

resource "aws_cloudwatch_event_target" "dr_readiness" {
  provider  = aws.dr
  count     = local.is_primary ? 1 : 0
  rule      = aws_cloudwatch_event_rule.dr_readiness[0].name
  target_id = "CodeBuild"
  arn       = aws_codebuild_project.dr_readiness[0].arn
  role_arn  = aws_iam_role.dr_readiness_events[0].arn
}

resource "aws_cloudwatch_metric_alarm" "rds_recovery_point_age" {
  provider            = aws.dr
  count               = local.is_primary ? 1 : 0
  alarm_name          = "${local.name}-rds-recovery-point-age"
  alarm_description   = "Latest replicated RDS recovery point is more than one hour old."
  namespace           = "Trishul/DR"
  metric_name         = "RDSBackupRecoveryPointAgeSeconds"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 900
  statistic           = "Maximum"
  threshold           = 3600
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.dr_operations[0].arn]
  ok_actions          = [aws_sns_topic.dr_operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "rds_replication_unhealthy" {
  provider            = aws.dr
  count               = local.is_primary ? 1 : 0
  alarm_name          = "${local.name}-rds-replication-unhealthy"
  alarm_description   = "RDS automated-backup replication is stopped, unhealthy, or unobservable."
  namespace           = "Trishul/DR"
  metric_name         = "RDSBackupReplicationHealthy"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  period              = 900
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.dr_operations[0].arn]
  ok_actions          = [aws_sns_topic.dr_operations[0].arn]
}
