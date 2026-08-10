output "bucket_name" { value = aws_s3_bucket.checkpoint.id }
output "kms_key_arn" { value = aws_kms_key.checkpoint.arn }
output "writer_role_arn" { value = local.writer_role_arn }
