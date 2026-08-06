moved {
  from = aws_s3_bucket.evidence
  to   = aws_s3_bucket.evidence[0]
}

moved {
  from = aws_s3_bucket_public_access_block.evidence
  to   = aws_s3_bucket_public_access_block.evidence[0]
}

moved {
  from = aws_s3_bucket_versioning.evidence
  to   = aws_s3_bucket_versioning.evidence[0]
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.evidence
  to   = aws_s3_bucket_server_side_encryption_configuration.evidence[0]
}

moved {
  from = aws_s3_bucket_policy.evidence
  to   = aws_s3_bucket_policy.evidence[0]
}

moved {
  from = aws_secretsmanager_secret.runtime
  to   = aws_secretsmanager_secret.runtime[0]
}
