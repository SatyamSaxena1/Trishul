# AWS shared-SaaS reference

This Terraform creates the production-pilot foundations: two-AZ VPC, public ALB subnets, private workload/data subnets, EKS with managed nodes and control-plane logging, multi-AZ RDS PostgreSQL 17, serverless Valkey, versioned KMS-encrypted S3 evidence storage, an empty Secrets Manager runtime reference, regional WAF, and an encrypted operations topic.

```sh
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config=backend.hcl
terraform validate
terraform plan -out trishul.tfplan
terraform apply trishul.tfplan
```

The state bucket and KMS key must already exist; migrate an existing local state with `terraform init -migrate-state -backend-config=backend.hcl`. First apply with `eks_public_endpoint_enabled=true`, configure the protected GitHub `production` environment variables from the Terraform outputs, run the deployment workflow, and confirm its `kubectl auth can-i` check. Then apply the default `false` value to close the public endpoint. All later Kubernetes deploys run inside the VPC-attached CodeBuild project.

Apply [`checkpoint/`](checkpoint/) in the security account first, then copy its bucket name and account ID into this root. The hourly AWS-overlay CronJob can only append checkpoint objects and emit its success metric; it has no checkpoint read, list, overwrite, or delete permission.

Install the AWS Load Balancer Controller with EKS workload identity, annotate the public edge Ingress with `terraform output -raw waf_acl_arn` and an ACM certificate ARN, and point CloudFront at that ALB. Populate the runtime secret through the approved secrets workflow and sync it with External Secrets; Terraform intentionally creates no secret values. Use the RDS-managed master secret only for migrations and create `trishul_app` as the non-bypass application role. The AWS overlay leaves `S3_ENDPOINT_URL` and static S3 credential files empty so boto3 uses EKS Pod Identity; the base and OpenShift profiles retain explicit object-store credentials for private deployments.

The shared tier is implemented here. Separate database/bucket/KMS resources for enterprise-isolated tenants and full dedicated-instance automation remain follow-up work. CloudFront, SES identity verification, Route 53, ACM, and multi-region disaster recovery remain account/domain-dependent integration steps.
