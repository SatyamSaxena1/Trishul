variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "dr_region" {
  type        = string
  default     = "ap-southeast-1"
  description = "Destination region for replicated data and recovery-mode compute."
}

variable "deployment_mode" {
  type        = string
  default     = "primary"
  description = "Primary manages replication; recovery restores the regional stack from replicated data."
  validation {
    condition     = contains(["primary", "recovery"], var.deployment_mode)
    error_message = "deployment_mode must be primary or recovery."
  }
}

variable "recovery_evidence_bucket_name" {
  type        = string
  default     = ""
  description = "Replicated evidence bucket to use in recovery mode."
}

variable "recovery_evidence_kms_key_arn" {
  type        = string
  default     = ""
  description = "Destination-region KMS key ARN used by the replicated evidence bucket."
}

variable "recovery_db_automated_backups_arn" {
  type        = string
  default     = ""
  description = "Destination-region automated-backup ARN used for latest-point-in-time recovery."
}

variable "recovery_runtime_secret_name" {
  type        = string
  default     = ""
  description = "Optional override for the replicated runtime secret name in recovery mode."
}

variable "recovery_drill" {
  type        = bool
  default     = false
  description = "Allows a non-production recovery drill to destroy its restored database without a final snapshot."
}

variable "environment" {
  type    = string
  default = "pilot"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "kubernetes_version" {
  type    = string
  default = "1.32"
}

variable "database_name" {
  type    = string
  default = "trishul"
}

variable "database_deletion_protection" {
  type    = bool
  default = true
}

variable "alert_email" {
  type        = string
  default     = ""
  description = "Optional address for the encrypted operations SNS topic. Subscription confirmation is required."
}

variable "eks_public_endpoint_enabled" {
  type        = bool
  default     = false
  description = "Temporary rollout escape hatch. Keep false after the VPC-attached deploy job is proven."
}

variable "github_repository" {
  type        = string
  description = "GitHub repository in owner/name form."
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must use owner/name form."
  }
}

variable "github_environment" {
  type        = string
  default     = "production"
  description = "Protected GitHub environment allowed to start deployment builds."
}

variable "github_oidc_provider_arn" {
  type        = string
  description = "ARN of the account's existing token.actions.githubusercontent.com IAM OIDC provider."
}

variable "codeconnections_connection_arn" {
  type        = string
  description = "ARN of an authorized CodeConnections connection for the GitHub repository."
}

variable "security_account_id" {
  type        = string
  description = "AWS account that owns the immutable audit checkpoint bucket."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.security_account_id))
    error_message = "security_account_id must be a 12-digit AWS account ID."
  }
}

variable "audit_checkpoint_bucket_name" {
  type        = string
  description = "Existing Object Lock bucket in the security account."
}

variable "audit_checkpoint_prefix" {
  type        = string
  default     = "audit-checkpoints"
  description = "Write-only prefix granted to the checkpoint publisher."
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9/_-]{0,127}$", var.audit_checkpoint_prefix)) && !strcontains(var.audit_checkpoint_prefix, "..") && !strcontains(var.audit_checkpoint_prefix, "//")
    error_message = "audit_checkpoint_prefix must be a safe, relative S3 prefix."
  }
}
