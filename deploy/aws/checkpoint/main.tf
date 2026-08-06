locals {
  writer_role_arn = "arn:aws:iam::${var.workload_account_id}:role/trishul-${var.environment}-checkpoint-writer"
  bucket_arn      = "arn:aws:s3:::${var.bucket_name}"
}

resource "aws_kms_key" "checkpoint" {
  description             = "Trishul immutable audit checkpoints"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SecurityAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.security_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "WorkloadCheckpointEncryption"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.workload_account_id}:root" }
        Action    = ["kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = {
          ArnEquals    = { "aws:PrincipalArn" = local.writer_role_arn }
          StringEquals = { "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:aws:s3:arn" = [local.bucket_arn, "${local.bucket_arn}/${var.checkpoint_prefix}/*"] }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "checkpoint" {
  name          = "alias/trishul-${var.environment}-audit-checkpoints"
  target_key_id = aws_kms_key.checkpoint.key_id
}

resource "aws_s3_bucket" "checkpoint" {
  bucket              = var.bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_public_access_block" "checkpoint" {
  bucket                  = aws_s3_bucket.checkpoint.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "checkpoint" {
  bucket = aws_s3_bucket.checkpoint.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "checkpoint" {
  bucket = aws_s3_bucket.checkpoint.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "checkpoint" {
  bucket = aws_s3_bucket.checkpoint.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.checkpoint.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "checkpoint" {
  bucket = aws_s3_bucket.checkpoint.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = var.retention_years
    }
  }
  depends_on = [aws_s3_bucket_versioning.checkpoint]
}

resource "aws_s3_bucket_policy" "checkpoint" {
  bucket = aws_s3_bucket.checkpoint.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AllowWriteOnlyCheckpointPublisher"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.workload_account_id}:root" }
        Action    = "s3:PutObject"
        Resource  = "${local.bucket_arn}/${var.checkpoint_prefix}/*"
        Condition = { ArnEquals = { "aws:PrincipalArn" = local.writer_role_arn } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.checkpoint]
}
