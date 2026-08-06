terraform {
  required_version = ">= 1.9.0"

  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.security_account_id]
  default_tags {
    tags = {
      Application = "trishul-cloud"
      Purpose     = "immutable-audit-checkpoints"
      ManagedBy   = "terraform"
    }
  }
}
