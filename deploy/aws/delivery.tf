resource "aws_security_group" "codebuild" {
  name_prefix = "${local.name}-codebuild-"
  description = "VPC-attached deployment runner"
  vpc_id      = aws_vpc.main.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "cluster_from_codebuild" {
  type                     = "ingress"
  security_group_id        = aws_security_group.eks_nodes.id
  source_security_group_id = aws_security_group.codebuild.id
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
}

resource "aws_iam_role" "codebuild" {
  name = "${local.name}-codebuild"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "codebuild.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "codebuild" {
  name = "deploy"
  role = aws_iam_role.codebuild.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["eks:DescribeCluster"]
        Resource = aws_eks_cluster.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeDhcpOptions",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:CreateNetworkInterfacePermission"]
        Resource = "arn:aws:ec2:${var.aws_region}:*:network-interface/*"
        Condition = {
          StringEquals = {
            "ec2:AuthorizedService" = "codebuild.amazonaws.com"
            "ec2:Subnet"            = [for subnet in aws_subnet.private : subnet.arn]
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.codebuild.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["codeconnections:UseConnection"]
        Resource = var.codeconnections_connection_arn
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "codebuild" {
  name              = "/trishul/${var.environment}/deploy"
  retention_in_days = 30
}

resource "aws_codebuild_project" "deploy" {
  name         = "${local.name}-deploy"
  service_role = aws_iam_role.codebuild.arn

  artifacts { type = "NO_ARTIFACTS" }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    environment_variable {
      name  = "TRISHUL_CLUSTER_NAME"
      value = aws_eks_cluster.main.name
    }
    environment_variable {
      name  = "TRISHUL_DB_HOST"
      value = aws_db_instance.postgres.address
    }
    environment_variable {
      name  = "TRISHUL_REDIS_HOST"
      value = aws_elasticache_serverless_cache.redis.endpoint[0].address
    }
    environment_variable {
      name  = "TRISHUL_S3_BUCKET"
      value = aws_s3_bucket.evidence.id
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/${var.github_repository}.git"
    git_clone_depth = 1
    buildspec       = "deploy/aws/buildspec.yml"
    auth {
      type     = "CODECONNECTIONS"
      resource = var.codeconnections_connection_arn
    }
  }

  logs_config {
    cloudwatch_logs { group_name = aws_cloudwatch_log_group.codebuild.name }
  }

  vpc_config {
    vpc_id             = aws_vpc.main.id
    subnets            = values(aws_subnet.private)[*].id
    security_group_ids = [aws_security_group.codebuild.id]
  }
}

resource "aws_eks_access_entry" "codebuild" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.codebuild.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "codebuild" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.codebuild.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
  depends_on = [aws_eks_access_entry.codebuild]
}

resource "aws_iam_role" "github_deploy" {
  name = "${local.name}-github-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repository}:environment:${var.github_environment}"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_deploy" {
  name = "start-codebuild"
  role = aws_iam_role.github_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["codebuild:StartBuild", "codebuild:BatchGetBuilds"]
      Resource = aws_codebuild_project.deploy.arn
    }]
  })
}
