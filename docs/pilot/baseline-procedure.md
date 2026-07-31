# Pilot baseline procedure

## Purpose and ownership

This procedure measures the complete pilot path: repository upload, archive validation, analysis,
human finding review, and risk disposition. The pilot owner runs it with an AppSec analyst and a
different risk approver. Use a dedicated non-production tenant and the release configuration that
will be piloted. Do not use unit-test or mocked analyzer results.

The run is successful only when every accepted repository reaches a terminal scan state, every
finding is reviewed, and each confirmed finding is linked to a scored risk with either remediation
or independently decided acceptance. Rejections intentionally exercised by the negative controls
do not make the golden path fail.

## Safety and cohort approval

1. Obtain written approval from the repository owner and security/data owner before staging any
   representative repository. Record the approval outside Git.
2. Prefer purpose-built synthetic repositories. Representative repositories must be scrubbed of
   secrets, personal data, credentials, customer data, proprietary issue text, and Git history.
3. Upload only ZIP or TAR exports containing the working tree. Run the organization's secret and
   malware scanners before staging. Never use a live production bucket or tenant.
4. Give each input an opaque cohort label outside the product (for example `SYN-PY-A`). Keep the
   label-to-source mapping and raw measurements in the approved restricted evidence store, not in
   this repository.
5. Freeze the cohort for a run. Include at least: one clean synthetic Python repository, one
   synthetic repository with a known instance of every supported rule, one approved representative
   Python repository, an identical resubmission, and negative archives for unsupported format,
   traversal/link, file-count, file-size, and expansion-limit validation.
6. Record only aggregate cohort composition (synthetic/representative and positive/negative counts)
   in Git. If a subgroup has fewer than five repositories, combine it into `other` to reduce
   re-identification risk.

## Before the run

1. Record release identifier, analyzer image digest, `python-stdlib` pack version, deployment class,
   allocated CPU/memory, concurrency, and UTC window in the restricted run log. Confirm readiness
   and that queue-depth/stale-lease alerts are visible.
2. Create the organization, workspace, application, and repository records through `/api/v1/`.
   Use a human AppSec identity for review, a human requester for risk acceptance, and a different
   authorized human approver. Do not put access tokens in the run log.
3. Start an append-only observation sheet in the restricted store. For every submission assign a
   random run-local ordinal and capture UTC timestamps for request start, HTTP response, queued,
   running, and terminal observation; response class; terminal state/error class; recovery action;
   finding rule IDs/statuses; risk disposition; and blockers. Do not copy source paths, snippets,
   titles, descriptions, repository names, user identities, UUIDs, or error text.
4. Define the observation interval (no more than 15 seconds), the stuck threshold (the larger of 30
   minutes or twice the configured analysis timeout), and the run timeout (recommended: two hours).
   Synchronize observer clocks. Check `/api/v1/health/ready` and record pass/fail.

## Execute the golden path

Perform the steps in order for each positive cohort input. Preserve the HTTP status and timestamps
in the restricted sheet, but do not commit request or response bodies.

1. **Upload and validation.** POST the archive as multipart field `archive` to
   `/api/v1/repositories/{repository_id}/imports/`. Count an HTTP `201` as accepted. Confirm the
   returned repository version has a SHA-256, size, and manifest. Resubmit the identical archive and
   verify it resolves to the same immutable version rather than duplicating content.
2. **Negative validation.** Submit each negative archive to the same endpoint. Count any response
   that creates no repository version as rejected, grouped only by validation category and HTTP
   status class. Unexpected acceptance is a blocker and the input must not be analyzed.
3. **Analysis.** POST the accepted repository-version ID, `python-stdlib`, and `1.0` to
   `/api/v1/scans/`. Poll `/api/v1/scans/{scan_id}/` and the corresponding `/api/v1/jobs/` record at
   the fixed interval until terminal. Do not retry or repair before the stuck threshold. Record each
   accepted scan request as one submitted job and exactly one terminal outcome.
4. **Finding review.** Retrieve findings filtered/associated to the scan. The AppSec analyst opens
   the evidence in the product, compares it with the approved oracle for synthetic cases, and sets
   each finding to `confirmed`, `false_positive`, or `needs_validation`, adding a non-sensitive
   rationale in the product. A candidate left unreviewed means the review step is incomplete.
5. **Duplicates.** Within a scan, count repeated fingerprints as duplicates. Across the identical
   resubmission, compare the aggregate fingerprint sets and count stable matches, missing matches,
   and unexpected additional matches. Store counts only. Do not copy fingerprints into Git.
6. **Risk handling.** For every confirmed finding, create a risk and a risk link, invoke
   `/api/v1/risks/{risk_id}/scores/` with the approved scoring inputs, then record one disposition:
   remediation created, acceptance approved, acceptance rejected, or open/undecided. Acceptance
   must be requested by a human and decided through `/api/v1/approvals/` by a different human.
   Confirm the audit events exist without exporting their identifiers.

## Recovery and blocker rules

- A job is **stuck** when it remains non-terminal past the defined stuck threshold. Count it once,
  preserve observations, then follow the approved operational runbook. A restart, requeue, database
  edit, queue purge, or resubmission is a **manual recovery** and must be counted by action category.
- A **rejected job** is a submission rejected before a `Job` is created. A **failed job** is an
  accepted submission whose scan/job reaches `failed`. Do not combine these counts.
- Do not silently retry. A resubmission is a new submitted job and must link to the original ordinal
  only in the restricted log.
- A **workflow blocker** prevents a required golden-path step or makes its result unobservable or
  unreliable. Stop the affected path, create/update a defect in `follow-up-defects.md`, and assign
  priority before proceeding. Record workarounds as manual steps; a workaround does not clear a
  blocker.
- Priority is `P0` for security/data loss or fleet-wide inability to run; `P1` for any required
  golden-path step that cannot complete or be measured; `P2` for a repeatable manual workaround or
  material accuracy/usability problem; and `P3` for minor friction.

## Calculations and reconciliation

Calculate from the restricted observation sheet, then enter aggregates in `baseline-results.md`:

- `submitted = completed + failed + cancelled + still_non_terminal` for accepted jobs.
- `completion rate = completed / submitted`. Report rejected submissions separately.
- Runtime is terminal observation minus accepted/queued observation. Report count, minimum, median
  (p50), p90, p95, maximum, and mean in seconds for completed jobs. State the percentile method
  (nearest-rank is preferred). Never calculate percentiles over failed or rejected submissions.
- Findings per rule are counts emitted and counts after analyst review. Combine any rule bucket that
  could reveal sensitive cohort details into `other`.
- Analyst outcomes must sum to reviewed findings; report unreviewed candidates separately.
- Report false-positive count and rate (`false_positive / reviewed`), within-scan duplicate count,
  and resubmission stability counts. These are observations, not a precision/recall claim. Synthetic
  oracle results may additionally report aggregate true-positive, false-positive, and false-negative
  counts when every expected case is independently enumerated outside Git.
- Report stuck jobs, manually recovered jobs, recovery action counts, blocker counts by priority,
  and manual-step counts by category. A job may be both stuck and manually recovered, so do not sum
  those two fields.

Reconcile totals independently by the pilot owner and analyst. The two people sign the restricted
record, then a reviewer checks the Git result for forbidden data. Commit only the aggregate results
and defect summaries. Keep raw logs, mappings, request/response bodies, evidence, and approvals in
the restricted store under its retention policy.

## Exit criteria

The baseline is complete when all aggregate fields are populated, equations reconcile, no positive
job remains non-terminal, all findings have an analyst outcome, all confirmed findings have a risk
disposition, and every golden-path blocker has a prioritized defect with an owner and acceptance
criteria. A P0 or P1 blocker makes the pilot decision **no-go** until verified closed in a new run.
