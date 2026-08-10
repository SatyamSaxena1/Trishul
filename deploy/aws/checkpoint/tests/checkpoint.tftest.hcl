mock_provider "aws" {}

run "compliance_locked_write_only_bucket" {
  command = plan

  variables {
    security_account_id = "210987654321"
    workload_account_id = "123456789012"
    bucket_name         = "security-audit-checkpoints"
  }

  assert {
    condition     = aws_s3_bucket.checkpoint.object_lock_enabled == true
    error_message = "Object Lock must be enabled when the bucket is created."
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.checkpoint.rule[0].default_retention[0].mode == "COMPLIANCE"
    error_message = "Checkpoint retention must use compliance mode."
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.checkpoint.rule[0].default_retention[0].years == 7
    error_message = "Checkpoint retention must default to seven years."
  }

  assert {
    condition     = !strcontains(aws_s3_bucket_policy.checkpoint.policy, "s3:GetObject") && !strcontains(aws_s3_bucket_policy.checkpoint.policy, "s3:DeleteObject")
    error_message = "The workload account bucket grant must remain write-only."
  }

  assert {
    condition     = !strcontains(aws_kms_key.checkpoint.policy, "kms:Decrypt")
    error_message = "The workload account must not receive checkpoint decrypt permission."
  }
}
