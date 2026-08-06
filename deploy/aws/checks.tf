check "recovery_inputs" {
  assert {
    condition = local.is_primary || (
      var.aws_region == var.dr_region &&
      var.recovery_evidence_bucket_name != "" &&
      can(regex("^arn:aws[a-z-]*:kms:[^:]+:[0-9]{12}:key/", var.recovery_evidence_kms_key_arn)) &&
      can(regex("^arn:aws[a-z-]*:rds:[^:]+:[0-9]{12}:auto-backup:", var.recovery_db_automated_backups_arn))
    )
    error_message = "Recovery mode must run in dr_region with the replicated evidence bucket and automated-backup ARN."
  }
}
