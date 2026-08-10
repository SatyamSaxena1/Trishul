resource "aws_eks_addon" "pod_identity" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "eks-pod-identity-agent"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_iam_role" "application" {
  name = "${local.name}-application${local.iam_suffix}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "pods.eks.amazonaws.com" }, Action = ["sts:AssumeRole", "sts:TagSession"] }]
  })
}

resource "aws_iam_role_policy" "application_storage" {
  name = "evidence-storage"
  role = aws_iam_role.application.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetBucketLocation", "s3:ListBucket"]
        Resource = local.evidence_bucket_arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${local.evidence_bucket_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = local.evidence_kms_key_arn
      },
    ]
  })
}

resource "aws_eks_pod_identity_association" "application" {
  for_each        = toset(["trishul-api", "trishul-worker"])
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "ai-trishul"
  service_account = each.value
  role_arn        = aws_iam_role.application.arn
  depends_on      = [aws_eks_addon.pod_identity]
}

resource "aws_iam_role" "checkpoint_writer" {
  count = local.is_primary ? 1 : 0
  name  = "${local.name}-checkpoint-writer"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "pods.eks.amazonaws.com" }, Action = ["sts:AssumeRole", "sts:TagSession"] }]
  })
}

resource "aws_iam_role_policy" "checkpoint_writer" {
  count = local.is_primary ? 1 : 0
  name  = "immutable-checkpoints"
  role  = aws_iam_role.checkpoint_writer[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "arn:aws:s3:::${var.audit_checkpoint_bucket_name}/${var.audit_checkpoint_prefix}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = "arn:aws:kms:${var.aws_region}:${var.security_account_id}:key/*"
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:aws:s3:arn" = ["arn:aws:s3:::${var.audit_checkpoint_bucket_name}", "arn:aws:s3:::${var.audit_checkpoint_bucket_name}/${var.audit_checkpoint_prefix}/*"] }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "Trishul/Operations" }
        }
      },
    ]
  })
}

data "aws_iam_role" "checkpoint_writer" {
  count = local.is_primary ? 0 : 1
  name  = "${local.name}-checkpoint-writer"
}

resource "aws_eks_pod_identity_association" "checkpoint_writer" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "ai-trishul"
  service_account = "trishul-checkpoint-writer"
  role_arn        = local.checkpoint_writer_role_arn
  depends_on      = [aws_eks_addon.pod_identity]
}

resource "aws_cloudwatch_metric_alarm" "checkpoint_missing" {
  alarm_name          = "${local.name}-audit-checkpoint-missing"
  alarm_description   = "No immutable audit checkpoint was published for two consecutive hours."
  namespace           = "Trishul/Operations"
  metric_name         = "AuditCheckpointPublished"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  period              = 3600
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
}
