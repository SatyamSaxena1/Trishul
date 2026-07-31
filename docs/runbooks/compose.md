# Docker Compose operations runbook

This runbook is for the supported single-host profile. It assumes the release is at
`/opt/trishul`; replace that path once, below, rather than editing individual commands.
Commands marked **destructive** require the incident/change record to contain peer
approval. Never paste secret values into a ticket or terminal transcript.

```sh
export TRISHUL_ROOT=/opt/trishul
cd "$TRISHUL_ROOT"
set -a; . "$TRISHUL_ROOT/.env"; set +a
export COMPOSE="docker compose --project-directory $TRISHUL_ROOT --env-file $TRISHUL_ROOT/.env -f $TRISHUL_ROOT/compose.yaml"
```

In expected output below, container names and timing may vary. “Healthy” means the
command exits zero and does not print secret data.

## 1. Host preparation

**Prerequisites.** A supported Linux host; root access for one-time setup; customer
approval for ports 443 and required outbound OIDC, S3, and model endpoints; DNS already
resolving to the host; 4 CPU, 12 GiB RAM, 50 GiB disk; Docker Engine and Compose v2
packages obtained from the customer's approved repository. Create a non-login
`trishul` service account and a distinct unprivileged `trishul-analyzer` account.

```sh
sudo install -d -o trishul -g trishul -m 0750 /opt/trishul
docker --version
docker compose version
getent hosts trishul.example.internal
df -h /opt/trishul && free -h && nproc
sudo -iu trishul-analyzer systemctl --user enable --now docker
sudo -iu trishul-analyzer docker context show
sudo -iu trishul-analyzer sh -lc 'test -S "$XDG_RUNTIME_DIR/docker.sock"'
```

**Expected safe output.** Version commands identify Docker and Compose v2; DNS returns
the approved address; capacity meets the values above; the context is rootless and the
socket test is silent with exit 0. **Success criteria.** Record the versions, address,
capacity, firewall change, service-account IDs, and rootless socket path in the change
record. **Failure handling.** Stop if the socket is `/run/docker.sock` or
`/var/run/docker.sock`, DNS is wrong, or capacity is insufficient; correct the host,
then repeat every check. **Rollback/escalation.** Before installation, remove the empty
directory and disable the analyzer user service to roll back. Escalate unsupported OS,
cgroup, rootless-runtime, proxy, or firewall constraints to the platform and security
owners; never substitute a rootful socket.

## 2. Configuration and secret provisioning

**Prerequisites.** Approved release contents in `$TRISHUL_ROOT`; OIDC metadata, S3
bucket and least-privilege credentials, model endpoint allowlist, TLS certificate/key,
and access to an approved secret generator or secrets manager.

```sh
cd "$TRISHUL_ROOT"
cp .env.example .env
chmod 0600 .env
${EDITOR:-vi} .env
install -d -m 0700 secrets
umask 077
openssl rand -base64 32 > secrets/db_owner_password
openssl rand -base64 32 > secrets/db_app_password
openssl rand -base64 32 > secrets/redis_password
openssl rand -base64 48 > secrets/django_secret_key
openssl rand -base64 32 > secrets/internal_ai_token
openssl rand -base64 32 > secrets/metrics_token
openssl rand -base64 32 > secrets/backup_key
# Materialize approved values without echoing them:
secret-manager read s3/access-key > secrets/s3_access_key
secret-manager read s3/secret-key > secrets/s3_secret_key
secret-manager read ai/credential > secrets/ai_endpoint_credential
secret-manager read tls/certificate > secrets/tls.crt
secret-manager read tls/private-key > secrets/tls.key
chmod 0600 secrets/*
sh bin/trishulctl doctor
```

Replace `secret-manager read ...` with the customer's non-logging CLI. Set every value
in `.env`, including digest-pinned production images and the rootless socket. Do not
store secrets in `.env`. Keep a separately protected recovery copy of `backup_key`.

**Expected safe output.** Doctor ends with `AI Trishul deployment prerequisites
passed`; no secret value is printed. **Success criteria.** All twelve files listed in
`secrets/README.md` are nonempty, mode 0600 or stricter, owned by the service account,
and the recovery key is escrowed. **Failure handling.** Delete and rematerialize any
partially written secret; correct only the named doctor error and rerun doctor. Avoid
`set -x`, shell history arguments, and `cat`. **Rollback/escalation.** Revoke newly
issued external credentials and securely remove local files if provisioning is
abandoned. Escalate mismatched certificates, inaccessible endpoints, or unavailable
recovery escrow to the respective service/security owner.

## 3. Clean installation

**Prerequisites.** Procedures 1–2 pass; signed images are built or loaded and their
digests verified; no prior `ai-trishul` containers or volumes exist; an approved
maintenance window.

```sh
cd "$TRISHUL_ROOT"
$COMPOSE ps -a
docker volume ls --filter label=com.docker.compose.project=ai-trishul
sh bin/trishulctl doctor
sh bin/trishulctl install
sh bin/trishulctl status
curl --fail --silent --show-error "https://${TRISHUL_HOSTNAME}/api/v1/health/live" >/dev/null
```

**Expected safe output.** The preflight lists no old resources; install ends `AI
Trishul is ready`; status shows long-running services `Up` and health checks healthy;
curl is silent. The one-shot `migrate` container may be `Exited (0)`.
**Success criteria.** HTTPS liveness and internal readiness pass, migrations exited zero, and no
service is restarting. **Failure handling.** Run `sh bin/trishulctl status` and
`sh bin/trishulctl logs migrate`; correct the first failing dependency or config and
rerun `install` (migrations are idempotent). **Rollback/escalation.** Before tenant
data exists, run `sh bin/trishulctl down`, then—with peer approval—`$COMPOSE down -v`.
Escalate migration errors before deleting anything; never use `down -v` on a deployment
that may contain data.

## 4. OIDC and first-tenant bootstrap

**Prerequisites.** Healthy clean installation; OIDC issuer/audience/client/redirect URI
registered for `https://$TRISHUL_HOSTNAME`; MFA claims configured; exact immutable OIDC
subject and verified email obtained out of band; tenant slug/name approved. Bootstrap
grants privileged initial access and requires two-person approval.

```sh
curl --fail --silent --show-error "$OIDC_JWKS_URL" >/dev/null
sh bin/trishulctl bootstrap 'OIDC-SUBJECT' 'admin@example.com' 'pilot' 'Pilot Tenant'
sh bin/trishulctl logs api
```

Then use a private browser, authenticate through OIDC with MFA, open the tenant, and
perform a read-only action. **Expected safe output.** Bootstrap reports creation (or a
clear already-existing conflict), logs show a successful authenticated request without
tokens, and the UI opens the correct tenant. **Success criteria.** The approved subject
can sign in with MFA and sees only the named tenant; a second unassigned test subject is
denied. **Failure handling.** Preserve the denial/correlation ID, compare issuer,
audience, subject and MFA claim names, and inspect redacted API logs. Do not weaken MFA
or audience checking. **Rollback/escalation.** Before data entry, disable the OIDC user
and abandon the tenant pending application-owner assisted removal. Escalate duplicate
subject/tenant, cross-tenant visibility, or successful non-MFA access immediately as a
security incident.

## 5. Normal restart and full host restart

**Prerequisites.** Healthy recent backup, no migration/backup/analysis collection in
progress, maintenance window, and access to both service accounts.

Normal application restart (preserves PostgreSQL and Redis):

```sh
$COMPOSE stop edge worker scheduler ai-gateway analysis-controller api
$COMPOSE start api worker scheduler ai-gateway analysis-controller edge
sh bin/trishulctl install
```

Full host restart:

```sh
sh bin/trishulctl down
sudo systemctl reboot
# After reconnecting:
sudo -iu trishul-analyzer systemctl --user is-active docker
cd "$TRISHUL_ROOT" && sh bin/trishulctl install
sh bin/trishulctl status
```

**Expected safe output.** Starts complete without errors, install ends `AI Trishul is
ready`, and status is healthy. **Success criteria.** Readiness passes and a queued test
job completes after each restart. **Failure handling.** If shutdown hangs, wait through
the analysis controller's 35-minute grace period; do not kill analyzer jobs unless the
incident commander accepts loss of that attempt. After boot, restore the rootless user
session/socket before the application. **Rollback/escalation.** A restart has no data
rollback. Leave edge stopped and escalate if database recovery, audit verification, or
rootless runtime startup fails repeatedly.

## 6. Backup creation and verification

**Prerequisites.** Sufficient space in `backups/`; protected `backup_key` and escrow
copy; an object-store versioned snapshot mechanism; no maintenance in progress. Backup
briefly stops application writes.

```sh
df -h "$TRISHUL_ROOT/backups"
sh bin/trishulctl backup
BACKUP_DIR=$(find "$TRISHUL_ROOT/backups" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
(cd "$BACKUP_DIR" && sha256sum -c SHA256SUMS)
test -s "$BACKUP_DIR/database.dump.enc"
test -s "$BACKUP_DIR/manifest.json"
stat -c '%a %n' "$BACKUP_DIR" "$BACKUP_DIR"/*
$COMPOSE run --rm migrate python manage.py verify_audit
```

At the same checkpoint, create a customer-managed, versioned S3 bucket snapshot and
record its immutable snapshot/version ID beside (not inside) the database backup.
**Expected safe output.** Backup prints `Encrypted backup created: ...`; checksum lines
end `OK`; audit verification exits zero; permissions expose nothing to group/other.
**Success criteria.** Encrypted dump, manifest, checksums, object snapshot ID, release
version, and separately escrowed key form one recovery set, and readiness is restored.
**Failure handling.** The script's trap attempts to restart writers. Confirm readiness,
retain failed artifacts for restricted diagnosis, and repeat with a new timestamp after
fixing space/dependency errors. **Rollback/escalation.** Backup itself needs no
rollback. Escalate inability to resume writes, checksum/audit failure, missing S3
snapshot, or lost escrow key; do not label the set recoverable until a clean restore
test passes.

## 7. Restore into a clean deployment

**Prerequisites.** Approved recovery set from procedure 6; matching `backup_key`;
compatible release; restored object-store snapshot; isolated clean host with no useful
volumes; ingress blocked; destructive-change peer approval. Never test restore over
production.

```sh
cd "$TRISHUL_ROOT"
$COMPOSE ps -a
docker volume ls --filter label=com.docker.compose.project=ai-trishul
(cd /secure/recovery/20260710T120000Z && sha256sum -c SHA256SUMS)
sh bin/trishulctl doctor
sh bin/trishulctl install
sh bin/trishulctl restore /secure/recovery/20260710T120000Z --confirm-restore
$COMPOSE run --rm migrate python manage.py verify_audit
sh bin/trishulctl status
```

Run OIDC, tenant-isolation, representative object download, and completed-job smoke
tests before opening ingress. **Expected safe output.** Checksums are `OK`, restore ends
`AI Trishul is ready`, audit verification exits zero, and smoke tests match the recorded
manifest. **Success criteria.** Database counts/checkpoints and sampled object hashes
match, authentication and isolation pass, and the recovery record names the snapshot
and release. **Failure handling.** Keep ingress closed, collect logs, and preserve the
source recovery set. Destroy only the failed *target* volumes with peer approval, fix
the cause, and retry from a new clean target. **Rollback/escalation.** Roll back by
returning traffic to the untouched source deployment. Escalate checksum, decryption,
schema, audit, object, or isolation mismatch; never continue from a partial restore.

## 8. Upgrade

**Prerequisites.** Approved signed/digest-pinned release, reviewed release notes and
schema compatibility, free disk, successful recent restore exercise, maintenance
window, rollback digests recorded, and a coordinated object-store snapshot plan.

```sh
cd "$TRISHUL_ROOT"
cp .env "/secure/change/.env.pre-upgrade.$(date -u +%Y%m%dT%H%M%SZ)"
sh bin/trishulctl doctor
sh bin/trishulctl backup
# Create and record the matching versioned object-store snapshot now.
${EDITOR:-vi} .env                 # change only approved image digests/tags
sh bin/trishulctl doctor
sh bin/trishulctl upgrade
sh bin/trishulctl status
$COMPOSE run --rm migrate python manage.py verify_audit
```

The `upgrade` command creates another backup by design, pulls non-buildable images,
migrates, replaces services, and waits for readiness. **Expected safe output.** Both
backups are created, pulls/migrations exit zero, readiness is reported, status is
healthy, and audit verification passes. **Success criteria.** Image IDs match the
approved release and OIDC, tenant isolation, object access, and a test job pass.
**Failure handling.** Stop the change, keep ingress closed if correctness is uncertain,
capture the failing migration/service logs, and determine whether a migration ran
before retrying. **Rollback/escalation.** Use procedure 9 only when the release matrix
says the migrated schema is backward compatible; otherwise restore the complete
pre-upgrade recovery set into a clean deployment. Escalate all migration, audit, data,
or isolation failures to the release owner.

## 9. Failed-upgrade rollback

**Prerequisites.** Incident/change owner, pre-upgrade `.env`, backup and object snapshot,
old image digests, migration outcome, and written confirmation of backward schema
compatibility. Keep ingress closed.

Compatible image rollback:

```sh
sh bin/trishulctl down
cp /secure/change/.env.pre-upgrade.TIMESTAMP .env
sh bin/trishulctl doctor
$COMPOSE pull --ignore-buildable
$COMPOSE up -d --remove-orphans
sh bin/trishulctl install
$COMPOSE run --rm migrate python manage.py verify_audit
```

If compatibility is not explicitly confirmed, do **not** run old images on the changed
database; follow procedure 7 using the pre-upgrade database backup and matching object
snapshot on a clean target. **Expected safe output.** The compatible path reaches
readiness with old approved image IDs and passes audit/smoke tests; the restore path
meets procedure 7 output. **Success criteria.** Version, schema, objects and audit
checkpoint form a supported set and regression tests pass before ingress opens.
**Failure handling.** Stop retrying after the same failure, preserve both release logs
and recovery artifacts, and keep the system isolated. **Rollback/escalation.** There is
no automatic destructive database downgrade. Escalate absent compatibility evidence,
partially applied migrations, or failed recovery immediately to release, database,
storage, and security owners.

## 10. Log and diagnostic collection

**Prerequisites.** Incident ID, approved restricted destination, minimum necessary time
window, and an operator authorized for logs. Logs may contain identifiers even though
application policy excludes source, evidence, prompts, responses, and secrets.

```sh
CASE=/secure/incidents/INC-0001
install -d -m 0700 "$CASE"
date -u +%FT%TZ > "$CASE/collected-at.txt"
sh bin/trishulctl status > "$CASE/compose-ps.txt" 2>&1
$COMPOSE logs --since 2h --timestamps > "$CASE/compose.log" 2>&1
docker info > "$CASE/docker-info.txt" 2>&1
df -h > "$CASE/df.txt" && free -h > "$CASE/free.txt"
$COMPOSE config --no-interpolate > "$CASE/compose-config.txt"
$COMPOSE run --rm migrate python manage.py verify_audit > "$CASE/audit.txt" 2>&1
find "$CASE" -type f -exec sha256sum {} \; > "$CASE/SHA256SUMS"
chmod -R go-rwx "$CASE"
```

Review and redact the bundle before transfer; never collect `.env`, `secrets/`, object
contents, database dumps, access tokens, or interpolated Compose configuration.
**Expected safe output.** Commands exit zero; files are nonempty where appropriate;
checksums are generated. **Success criteria.** Bundle has incident/time/release context,
minimal relevant logs, audit result, restricted permissions, and a documented custody
path. **Failure handling.** If collection risks disk pressure, stream directly to the
approved collector or narrow `--since`; if a command fails, record its stderr and
continue with non-invasive checks. **Rollback/escalation.** Delete working copies after
accepted transfer and retention approval. Escalate suspected secret/evidence exposure
to the incident commander before sharing the bundle.

## 11. Disk-pressure response

**Prerequisites.** Disk alert or `df` confirmation, incident record, and knowledge of
the approved log/backup retention policy. Do not delete Docker volumes or current
recovery sets.

```sh
df -h "$TRISHUL_ROOT" /var/lib/docker
docker system df
du -x -h -d 1 "$TRISHUL_ROOT/backups" /var/lib/docker 2>/dev/null | sort -h
$COMPOSE ps
$COMPOSE logs --tail=200
```

First stop ingestion/jobs through the application and, if free space is still falling,
stop writers:

```sh
$COMPOSE stop edge worker scheduler ai-gateway analysis-controller api
docker image prune -f
docker builder prune -f --filter until=168h
df -h "$TRISHUL_ROOT" /var/lib/docker
$COMPOSE start api worker scheduler ai-gateway analysis-controller edge
sh bin/trishulctl install
```

Delete expired logs/backups only through customer retention procedures after verifying
another recovery copy. **Expected safe output.** Prune reports reclaimed cache/unused
images, free space stabilizes above the alert threshold, and readiness returns.
**Success criteria.** Root cause and reclaimed items are recorded, sufficient headroom
exists for backup/migration, and a new verified backup can complete. **Failure handling.** Keep writers stopped if PostgreSQL has no safe headroom; add/extend storage
rather than using `docker system prune --volumes`. **Rollback/escalation.** Pruned
images may be reloaded from the signed release. Escalate filesystem errors, continued
growth, PostgreSQL errors, or any proposal to delete volumes/current backups.

## 12. Stuck-job response

**Prerequisites.** Job/correlation and tenant IDs, authorization for that tenant,
confirmed age beyond its lease/SLO, and no active backup/upgrade. Never inspect evidence
from another tenant.

```sh
$COMPOSE ps
$COMPOSE logs --since 30m worker analysis-controller
$COMPOSE exec -T redis sh -c 'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" ping'
$COMPOSE exec -T worker celery -A trishul inspect active
$COMPOSE exec -T worker celery -A trishul inspect reserved
$COMPOSE exec -T analysis-controller celery -A trishul inspect active
sudo -iu trishul-analyzer docker ps --no-trunc
```

**Expected safe output.** Redis says `PONG`; Celery returns worker replies; runtime jobs
correlate with the incident without printing payloads. **Success criteria.** Determine
whether the job is queued, leased, or running and let the lease-expiry task mark truly
stale work failed; resubmit through the normal UI/API only after that transition.
**Failure handling.** Restart only the affected worker using `$COMPOSE restart worker`
or `$COMPOSE restart analysis-controller`, then wait for readiness and lease expiry.
Do not edit job rows, purge the queue, or kill an analyzer merely because it is slow.
**Rollback/escalation.** Restart is reversible by starting the service. Escalate before
force-removing a runtime container, when jobs span tenants, leases repeatedly expire,
or queue/storage/database health is impaired.

## 13. Storage and identity outages

**Prerequisites.** Dependency alert, incident commander, customer S3/OIDC contacts,
and approved endpoint/CA details. Treat TLS failures as security failures, not as a
reason to disable verification.

```sh
sh bin/trishulctl status
$COMPOSE logs --since 30m api worker ai-gateway
curl --fail --silent --show-error "$OIDC_JWKS_URL" >/dev/null
curl --fail --silent --show-error "https://${TRISHUL_HOSTNAME}/api/v1/health/ready" >/dev/null
```

For S3 outage, stop new ingestion and workers while preserving database and queued
state: `$COMPOSE stop worker analysis-controller`. For OIDC outage, do not bootstrap
alternate subjects or bypass authentication; existing sessions are subject to normal
expiry. **Expected safe output.** Healthy dependency probes are silent; failures retain
HTTP/TLS/DNS error text without credentials; recovery makes readiness pass. **Success criteria.** Provider confirms recovery, endpoint certificate/issuer is unchanged or
approved, workers restart, and a tenant-authorized object and OIDC smoke test pass.
**Failure handling.** Keep affected processing paused, retry with bounded intervals,
and validate DNS/time/CA chain. Never set insecure TLS flags or point at an unapproved
bucket/issuer. **Rollback/escalation.** Revert an approved endpoint/CA configuration
change if it fails doctor/readiness. Escalate unexpected certificate, issuer, bucket,
or data changes immediately to security and the dependency owner.

## 14. Security incident containment

**Prerequisites.** Security incident declaration, incident commander, evidence/custody
location, and console access independent of possibly compromised OIDC.

```sh
CASE=/secure/incidents/SEC-0001
install -d -m 0700 "$CASE"
date -u +%FT%TZ | tee "$CASE/containment-start.txt"
$COMPOSE ps > "$CASE/compose-ps.txt"
$COMPOSE logs --since 4h --timestamps > "$CASE/pre-containment.log" 2>&1
$COMPOSE stop edge worker scheduler ai-gateway analysis-controller api
$COMPOSE run --rm migrate python manage.py verify_audit > "$CASE/audit.txt" 2>&1
sha256sum "$CASE"/* > "$CASE/SHA256SUMS"
```

At customer controls, block ingress and unnecessary egress, disable implicated OIDC
subjects/service credentials, preserve host/cloud/object audit logs and versioned
objects, and snapshot disks using forensic policy. Rotate credentials only after
preservation, from a known-clean workstation; do not overwrite originals or destroy
containers. **Expected safe output.** Public edge and processing services are stopped,
database/Redis remain available for preservation, and collected artifacts have hashes.
**Success criteria.** Unauthorized access is contained, volatile evidence and custody
are recorded, audit-chain result is preserved, and every rotation/revocation is tracked.
**Failure handling.** If local commands may alert an attacker or alter evidence, isolate
at the network/hypervisor layer and defer to forensics. **Rollback/escalation.** Only the
incident commander may authorize re-enabling services, after clean-image restore,
credential rotation, audit/tenant-isolation checks, and monitoring. Escalate audit
failure, secret exposure, cross-tenant access, or destructive activity immediately to
legal/privacy and customer security teams.

## 15. Secure pilot-data deletion

**Prerequisites.** Written scope (tenant or entire pilot), legal/retention approval,
two-person authorization, export/hold decision, inventory of database, object versions,
backups, logs and external replicas, and an agreed deletion certificate. Ordinary file
deletion is not proof of deletion on snapshots or SSDs.

The MVP has no supported per-tenant purge command. For a **whole-pilot teardown**, stop
all processing, preserve only legally required evidence, then use customer-native
cryptographic deletion for object versions, backups and escrowed keys. Finally:

```sh
sh bin/trishulctl down
# DESTRUCTIVE: verify the project and peer approval immediately before execution.
$COMPOSE ps -a
docker volume ls --filter label=com.docker.compose.project=ai-trishul
$COMPOSE down -v --remove-orphans
find "$TRISHUL_ROOT/backups" -mindepth 1 -maxdepth 1 -type d -print
# Delete only the reviewed backup paths via the approved secure-deletion system.
```

Revoke S3/AI/database credentials; delete all bucket object versions and delete markers
under the customer retention system; expire replicated backups; destroy the pilot's
backup/data-encryption keys in the secrets manager; remove approved logs and diagnostic
bundles at retention expiry. Do not use `rm` as the sole assurance for encrypted or
replicated storage. **Expected safe output.** Compose reports named containers/networks
and data volumes removed; inventory queries show zero in-scope live/versioned objects,
recoverable backups, credentials, and keys. **Success criteria.** An independent reviewer
reconciles every inventory location and signs a deletion certificate with timestamps,
scope, commands/system records, key IDs, exceptions, and retention expiries. **Failure handling.** Stop on an unexpected project/volume name, legal hold, inaccessible replica,
or partial provider deletion; preserve logs and reopen the task with the system owner.
**Rollback/escalation.** Secure deletion is intentionally irreversible; there is no
rollback. Escalate any tenant-only deletion request (unsupported), shared-resource
ambiguity, retained replica, failed key destruction, or inability to prove deletion to
privacy, legal, security, storage, and application owners.
