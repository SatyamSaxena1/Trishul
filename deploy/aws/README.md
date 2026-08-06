# AWS shared-SaaS reference

This Terraform creates the production-pilot foundations: two-AZ VPC, public ALB subnets, private workload/data subnets, EKS with managed nodes and control-plane logging, multi-AZ RDS PostgreSQL 17, serverless Valkey, versioned KMS-encrypted S3 evidence storage, an empty Secrets Manager runtime reference, regional WAF, and an encrypted operations topic.

```sh
terraform init
terraform validate
terraform plan -out trishul.tfplan
terraform apply trishul.tfplan
aws eks update-kubeconfig --name "$(terraform output -raw cluster_name)"
kubectl apply -k ../kubernetes/base
```

Install the AWS Load Balancer Controller with EKS workload identity, annotate the public edge Ingress with `terraform output -raw waf_acl_arn` and an ACM certificate ARN, and point CloudFront at that ALB. Populate the runtime secret through the approved secrets workflow and sync it with External Secrets; Terraform intentionally creates no secret values. Use the RDS-managed master secret only for migrations and create `trishul_app` as the non-bypass application role.

The shared tier is implemented here. Separate database/bucket/KMS resources for enterprise-isolated tenants and full dedicated-instance automation remain follow-up work. CloudFront, SES identity verification, Route 53, ACM, private EKS endpoint enforcement, and multi-region disaster recovery are account/domain-dependent integration steps, not claimed as deployed by this stack.
