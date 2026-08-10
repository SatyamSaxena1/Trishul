# Immutable audit checkpoints

Apply this root in the security account before the workload stack. Its bucket policy names the deterministic workload writer role through an account-root principal condition, so the role does not need to exist yet.

```sh
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config=backend.hcl
terraform apply
```

Object Lock compliance mode cannot be shortened or bypassed. Confirm the retention requirement before the first apply. After both stacks are applied, assume the writer role and verify that `PutObject` succeeds while `ListBucket`, `GetObject`, and `DeleteObject` return access denied. S3 permits a same-key write as a new version; it cannot replace or delete the already locked version, and the publisher uses unique timestamped keys. Readers use a separate security-account role that is never associated with a Trishul pod.
