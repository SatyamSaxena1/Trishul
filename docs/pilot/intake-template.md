# Pilot repository intake template

Use one copy of this form for each repository considered for the ten-repository
Python language-pack pilot. The completed form is an operational security record,
not project documentation: store it in the approved access-controlled pilot system
and **do not commit it to Git**. Use an opaque pilot ID in schedules, tickets, test
results, and regression records. Do not put customer or repository names, source
code, credentials, finding details, personal data, internal URLs, or other sensitive
metadata in this repository.

## Intake record

### Record control

- **Pilot ID (opaque; for example, `PILOT-001`):**
- **Record owner:**
- **Intake date:**
- **Record storage location / access-control group:**
- **Status:** proposed / approved / rejected / withdrawn / deleted

### Repository and authorization

- **Repository identifier (record only in the controlled system):**
- **Repository owner / accountable organization:**
- **Owner contact:**
- **Exact revision, tag, or immutable digest authorized for analysis:**
- **Written authorization reference (approval or contract ID; do not paste the
  authorization into Git):**
- **Authorization scope and restrictions:**
- **Authorized by (name/role):**
- **Authorization date and expiry date:**
- **Authorization verified by / date:**

The authorization must explicitly cover acquisition, unpacking, automated security
analysis, storage of results, human review, and the processing location. It must also
identify any prohibited processing. An owner assertion without a retrievable written
approval is not sufficient.

### Technical profile

- **Python version(s) used in production and CI:**
- **Python syntax minimum and maximum:**
- **Framework(s) and exact version(s), including “standard library only” where
  applicable:**
- **Dependency/packaging format(s):**
- **Approximate total file count:**
- **Approximate Python file count:**
- **Archive format and approximate compressed size:**
- **Approximate uncompressed size:**
- **Monorepo or generated/vendor content notes:**
- **How the values above were measured:**

### Data handling

- **Sensitive-data classification:** public / internal / confidential / restricted
- **Classification authority and policy reference:**
- **Expected sensitive-data types (describe by category, not by value):**
- **Secret and personal-data scan completed by / date / tool:**
- **Scan disposition:** passed / sanitized and re-scanned / rejected
- **Approved processing environment and region:**
- **Required handling controls:**

Never copy credentials, secrets, personal data, source excerpts, filenames, customer
names, private dependency names, internal hostnames, or finding evidence into this
form's Git-hosted blank template, a Git issue, or a commit message. Record sensitive
details only in the controlled system.

### Existing security knowledge

- **Are known security findings available?** yes / no / unknown
- **Approved finding-set reference and assessment date:**
- **Ground-truth quality:** confirmed / triaged / unreviewed
- **Finding categories and aggregate count (if disclosure is approved):**
- **Reviewer permitted to access the detailed findings:**

Reference the approved finding set rather than reproducing source snippets, paths,
vulnerability details, or report contents in Git. “No” and “unknown” are valid and
must not be interpreted as evidence that the repository has no vulnerabilities.

### Review assignment

- **Primary security reviewer:**
- **Independent secondary reviewer:**
- **Repository/framework subject-matter reviewer:**
- **Conflict-of-interest check completed by / date:**
- **Target review completion date:**
- **Escalation owner:**

### Retention, deletion, and regression use

- **Retention begins:**
- **Expected retention end date:**
- **Expected deletion date:**
- **Systems/copies covered (archive, extracted files, results, logs, backups):**
- **Deletion owner and verification method:**
- **Legal or contractual hold:** none / reference
- **May the repository be retained in a regression corpus?** yes / no
- **Regression authorization reference, approver, date, and expiry:**
- **Permitted corpus artifacts:** full archive / minimized reproducer / derived
  non-reconstructive fixture / metrics only
- **Corpus access, location, and revalidation cadence:**

Pilot analysis authorization does not imply regression-corpus authorization. Treat
“no,” blank, expired, or ambiguous approval as **no**. Delete every retained copy by
the earliest applicable authorization, contract, policy, or retention deadline and
record deletion evidence in the controlled system.

### AI-assisted processing

- **Will any AI-assisted processing occur?** yes / no
- **Explicit AI-processing approval:** approved / denied
- **Approval reference, approver, date, and expiry:**
- **Approved provider, model/service, endpoint, and processing region:**
- **Data permitted to be sent:**
- **Data prohibited from being sent:**
- **Provider retention/training terms accepted by:**
- **Human reviewer and required validation:**

“No” or blank approval means AI-assisted processing is prohibited. Approval must be
specific to the provider and data classes involved; general analysis authorization
is not sufficient. The deterministic analyzer may proceed only if the separate
repository authorization and all handling requirements permit it.

### Final decision

- **All mandatory fields complete:** yes / no
- **Selection gates below satisfied:** yes / no
- **Exceptions and approving authority:**
- **Approved for pilot by / date:**
- **Owner acknowledgement of retention, deletion, regression, and AI choices:**

## Ten-repository selection criteria

Select exactly ten repositories only after completing intake. Maintain the candidate
list and repository-to-slot mapping in the controlled pilot system using pilot IDs;
Git may contain only this method and aggregate, non-identifying results.

### Mandatory gates for every repository

1. A repository owner and a precise revision are identified, and retrievable written
   authorization covers the planned analysis and processing location.
2. Python and framework versions are evidenced by maintained configuration, CI, or
   owner attestation. The code falls within the Python language pack's supported
   matrix in the release being evaluated; record that release's authoritative matrix
   reference rather than inferring support from the analyzer runtime.
3. File count, Python file count, compressed size, and uncompressed size are measured
   or reasonably estimated and fit the approved archive and analysis limits.
4. Data classification and handling controls are approved. Pre-ingestion scanning
   finds no credentials or unapproved sensitive data; sanitize and re-scan, or reject.
5. A primary and independent secondary reviewer are assigned and can access the
   evidence needed to adjudicate results.
6. Retention and deletion dates, a deletion owner, and a verification method are set.
   Regression retention and AI processing each require separate, explicit approval.
7. The repository is not selected merely because it is easy to obtain, and the owner
   agrees that participation does not guarantee a favorable assessment.

### Portfolio coverage and allocation

Before selecting candidates, copy the authoritative supported Python-version and
framework matrix for the exact language-pack release into the controlled selection
record. Build a coverage table whose rows are supported Python minors and whose
columns are supported framework families (including a no-framework/standard-library
column where supported), then allocate the ten slots as follows:

1. Give every supported Python minor at least one repository. If there are more than
   ten supported minors, do not start the pilot; increase the approved cohort or
   narrow the declared support matrix rather than silently omitting a version.
2. Give every explicitly supported framework family at least one repository. A single
   repository may cover one Python-minor/framework cell, but no repository may count
   twice for the same dimension.
3. Use the remaining slots to cover common intersections and boundaries: the oldest
   and newest supported Python minor, oldest and newest supported framework branches,
   standard-library-only code, and at least one repository that uses multiple
   supported frameworks when available.
4. Include varied scale: at least two small, two medium, and two large repositories,
   with size-band thresholds fixed in the controlled record before candidates are
   scored. Include both single-package and multi-package/monorepo layouts when the
   authorized candidate pool permits.
5. Include varied packaging and test conventions (for example, `pyproject.toml` and
   legacy supported formats) and both synchronous and asynchronous application styles
   where they are part of the supported matrix.
6. Prefer repositories with adjudicated findings for measuring recall, but reserve at
   least two slots for repositories without a supplied finding set to assess review
   workflow and unexpected-result handling. Do not weaken authorization or handling
   gates to obtain ground truth.
7. Cap any one owner at two repositories and any one Python-minor/framework cell at
   three repositories, unless a documented exception is approved. This prevents one
   customer or stack from dominating the evidence.
8. Rank eligible candidates using only coarse, non-identifying attributes: uncovered
   matrix cells first, then boundary coverage, framework diversity, size/layout
   diversity, and ground-truth quality. Break ties by a documented random draw, not
   customer prominence or reviewer preference.

### Selection record and acceptance check

For slots 1 through 10, record only in the controlled system: pilot ID, selected
Python minor, framework family/version band, size band, layout/packaging category,
ground-truth availability, reviewer IDs, approvals, and the reason for selection.
Before ingestion, a person independent of candidate ranking must verify that:

- there are exactly ten unique repository revisions;
- every supported Python minor and supported framework family has coverage;
- the oldest/newest boundaries and required diversity targets are met;
- all ten records passed every mandatory gate and have unexpired approvals; and
- no customer names, source, credentials, sensitive metadata, intake forms, or
  repository-to-pilot-ID mappings have been committed to Git.

If any check fails, replace or remediate the candidate before analysis. Changes to the
supported matrix require the coverage exercise and approval check to be repeated.
