mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["ap-south-1a", "ap-south-1b", "ap-south-1c"]
    }
  }
}

run "private_cluster_and_workload_identity" {
  command = plan

  variables {
    github_repository              = "example/trishul"
    github_oidc_provider_arn       = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    codeconnections_connection_arn = "arn:aws:codeconnections:ap-south-1:123456789012:connection/00000000-0000-0000-0000-000000000000"
    security_account_id            = "210987654321"
    audit_checkpoint_bucket_name   = "security-audit-checkpoints"
  }

  assert {
    condition     = aws_eks_cluster.main.vpc_config[0].endpoint_public_access == false
    error_message = "The production default must keep the EKS endpoint private."
  }

  assert {
    condition     = length(aws_eks_pod_identity_association.application) == 2
    error_message = "Only the API and worker service accounts receive the application role."
  }

  assert {
    condition     = !contains(keys(aws_eks_pod_identity_association.application), "trishul-analysis-controller")
    error_message = "The analyzer controller must not receive application AWS credentials."
  }

  assert {
    condition     = aws_eks_pod_identity_association.checkpoint_writer.service_account == "trishul-checkpoint-writer"
    error_message = "Only the checkpoint CronJob receives the cross-account writer role."
  }
}
