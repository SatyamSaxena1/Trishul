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
  region = var.aws_region

  default_tags {
    tags = {
      Application = "trishul-cloud"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

provider "aws" {
  alias  = "dr"
  region = var.dr_region

  default_tags {
    tags = {
      Application = "trishul-cloud"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
