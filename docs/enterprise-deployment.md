# Kubernetes and OpenShift deployment

This is the enterprise orchestration profile. It uses the same application images and contracts as Compose; it does not add a second application implementation. The supplied Kustomize base includes replicas, disruption budgets, horizontal pod autoscaling, restricted pod security, default-deny networking, least-privilege analysis-controller RBAC, ingress, and externalized state.

## Customer overlay

Copy `deploy/kubernetes/site/kustomization.example.yaml` to `deploy/kubernetes/site/kustomization.yaml` and replace every example hostname and digest. Set `TRISHUL_KUSTOMIZE_DIR` to that directory. For OpenShift, make the customer overlay reference `deploy/kubernetes/openshift` instead of `base`; the Route replaces the generic Ingress and pods remain compatible with arbitrary non-root UIDs.

Create namespace `ai-trishul`, then provision `trishul-runtime-secrets` and `trishul-ai-credential` through the customer's external-secrets controller. `secret.example.yaml` documents required keys and must never be applied with real values from source control. Secrets are projected only into their authorized single-container pods and are absent from pod environment variables. Restart affected workloads after rotating a subPath-mounted AI credential.

Copy `external-egress.example.yaml` outside the repository and replace the documentation CIDRs with the resolved, reviewed CIDRs for PostgreSQL, Redis, S3, OIDC, model endpoints, the Kubernetes API, and the ingress controller as applicable. The base is fail-closed: workloads cannot reach external dependencies until this policy is applied. Revalidate policies whenever endpoint addresses change.

## Install

Load signed, digest-pinned release images into the approved internal registry before restricted-network installation. No chart repository or public registry is needed at runtime.

```text
export TRISHUL_IMAGE=registry.customer/ai-trishul@sha256:<digest>
export TRISHUL_KUSTOMIZE_DIR=/secure/trishul-overlay
export TRISHUL_CONFIG_PATCH=/secure/config.patch.yaml
export TRISHUL_EGRESS_POLICY=/secure/trishul-egress.yaml
sh bin/trishulkube doctor
sh bin/trishulkube install
```

The installer creates a one-shot migration Job before starting workloads, then health-gates every Deployment. The analysis controller can create and delete only Jobs and scratch PVCs. Analyzer pods receive no service-account token, application secret, database credential, or network access. Short-lived presigned object URLs are used by separate staging and collection jobs.

Set `KUBE_SCRATCH_STORAGE_CLASS` when the default class is unsuitable. Set `KUBE_FS_GROUP` only when the selected CSI driver requires it. Keep `KUBE_ENFORCE_IMAGE_UID=false` on OpenShift so its security context constraint can assign the UID.

## Upgrade and rollback

Before upgrade, create and verify a coordinated external PostgreSQL and object-store checkpoint. Load and verify the new images, update overlay digests, then run:

```text
export TRISHUL_BACKUP_CONFIRMED=yes
sh bin/trishulkube upgrade
```

Migrations must remain expand/contract compatible. Roll back image digests only while the migrated schema supports the prior release; destructive database rollback is never automatic.

## Backup and recovery

PostgreSQL, Redis, object storage, secret wrapping keys, and ingress certificates are external enterprise services and must use their customer-approved backup systems. A recovery set includes the PostgreSQL backup, versioned object-store snapshot, application release manifest and SBOM, customer overlay, external-secret references, audit checkpoints, and encryption keys stored separately. Restore into an empty namespace and clean data services, verify object hashes and the audit chain, run `trishulkube install`, then execute tenant-isolation and authentication smoke tests before reopening ingress.

## Observability and scaling

Scrape `/api/v1/metrics` over the internal service using the mounted metrics token. Ship structured stdout/stderr logs to the customer collector. HPA scales API and ordinary workers; queue-depth scaling can replace CPU HPA when the customer's metrics adapter is available. Central alerting must cover readiness, queue leases, analyzer failures, policy denials, external dependencies, backup age, and audit-checkpoint verification.
