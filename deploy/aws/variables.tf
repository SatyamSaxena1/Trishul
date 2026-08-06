variable "aws_region" {
  type    = string
  default = "ap-south-1"
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
