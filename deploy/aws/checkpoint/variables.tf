variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "environment" {
  type    = string
  default = "pilot"
}

variable "security_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.security_account_id))
    error_message = "security_account_id must be a 12-digit AWS account ID."
  }
}

variable "workload_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.workload_account_id))
    error_message = "workload_account_id must be a 12-digit AWS account ID."
  }
}

variable "bucket_name" {
  type = string
}

variable "checkpoint_prefix" {
  type    = string
  default = "audit-checkpoints"
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9/_-]{0,127}$", var.checkpoint_prefix)) && !strcontains(var.checkpoint_prefix, "..") && !strcontains(var.checkpoint_prefix, "//")
    error_message = "checkpoint_prefix must be a safe, relative S3 prefix."
  }
}

variable "retention_years" {
  type    = number
  default = 7
  validation {
    condition     = var.retention_years >= 1 && var.retention_years <= 100
    error_message = "retention_years must be between 1 and 100."
  }
}
