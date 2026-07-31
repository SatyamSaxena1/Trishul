# Pilot qualification report — 2026-07-31

## Result

**BLOCKED; not qualified.** No production-like deployment was opened and no claim of backup, recovery, or rollback success is made. The supplied execution host did not meet the documented pilot minimum and did not permit a Docker network to be created. Testing stopped at the clean-install safety gate.

## Non-sensitive environment and evidence

- Report ID: `QUAL-20260731-01`; source revision under test: `5c486524a73db68529354f340af174bf5b45b458`.
- Host: Ubuntu 24.04.4 LTS, Linux 6.12.13 x86_64; 3 online CPUs, approximately 17.9 GiB RAM, and approximately 27.6 GiB free on a 62.4 GiB filesystem.
- Docker 29.1.3 and Compose 2.40.3 were installed as the only operator intervention. Starting the daemon failed while creating its NAT chain because this execution environment does not grant network-administration capability.
- No credentials, tenant identifiers, tokens, repository contents, or object keys were recorded. No deployment state or customer data was created.

## Attempts, durations, and discrepancies

| Step | Attempt | Duration | Result | Intervention / sanitized evidence |
|---|---:|---:|---|---|
| Clean-install prerequisite check | 1 | <1 s | Failed | Docker executable was absent. Installed distribution Docker/Compose packages. |
| Docker daemon start | 1 | 10 s | Failed | Daemon reported permission denied while creating the Docker NAT chain. No network or container was created. |
| `trishulctl doctor` | 1 | 218 ms | Failed | Correctly rejected the absent `.env`; configuration and secrets were not invented because the required OIDC/S3 services were unavailable. |
| Host sizing comparison | 1 | <1 s | Failed | 3 online CPUs versus the documented minimum of 4. |
| Corrected `trishulctl doctor` | 2 | 558 ms | Failed as expected | With non-sensitive placeholder configuration and a temporary Unix-socket fixture, the corrected check rejected the host: at least 4 online CPU cores required, 3 found. Fixtures were removed immediately. |
| Steps 2–9 | 0 | n/a | Blocked | A clean installation is a mandatory dependency; proceeding would invalidate qualification. |

## Runbook corrections and repeat status

The prior operations runbook did not define synthetic fixtures, coordinated checkpoint identifiers, isolation evidence, authentication/tenant negative tests, controlled failure placement, rollback decision rules, timings, or a report format. The new pilot qualification runbook now specifies these items and requires failed and dependent steps to be rerun from a clean boundary.

The prerequisite checker was corrected to enforce the documented CPU and memory minimums. A full rerun remains blocked: this host has only 3 online CPUs and cannot run the required container networking. Qualification must restart at step 1 on a clean Linux VM with at least 4 CPUs and the capabilities needed by Docker, plus reachable disposable OIDC and S3-compatible services and releases `N-1` and `N`.

## Conclusion

Operator conclusion: **not qualified**. There is no evidence on this host for a completed scan, coordinated database/object snapshot, restore, upgrade failure, rollback, or data-loss check. Those gates must not be marked passed until the new runbook is executed end to end and independently witnessed on a compatible VM.
