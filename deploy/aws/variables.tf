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
