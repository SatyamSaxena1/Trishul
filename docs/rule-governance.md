# Rule pilot governance

## Promotion gate

A rule version remains disabled or experimental until **all** of these gates have evidence in its promotion record:

1. The version passes the checked-in regression corpus deterministically: identical input, configuration, and analyzer image digest produce identical normalized finding JSON and fingerprints on two clean runs.
2. Every emitted finding has complete provenance: rule ID and version, pack and pack version, configuration version, repository-version identity, analyzer image digest, file path, line range, snippet hash, and finding fingerprint. A promotion review must block on any absent field.
3. The security review has no open critical false-positive pattern. A pattern is critical when it can systematically mislabel safe code as a high/critical finding or create an unsafe remediation recommendation; isolated false positives still count in usefulness.
4. At least **10 independently reviewed findings per rule version**, drawn from at least two repositories when available, have one terminal outcome: accepted, false positive, duplicate, or needs context.
5. Usefulness (`accepted / all reviewed`) is at least **70%**, matching the overall pilot target. The overall report must also remain at least 70%; rounding never promotes a rule below the threshold.

Passing regression tests alone does not promote a rule. The current pilot report therefore supports promotion of PY001 and PY002, subject to recorded provenance and critical-pattern review; PY003 remains experimental at 60% usefulness.

## Approval and configuration changes

The **Detection Engineering owner** proposes a version and supplies regression, provenance, sampling, and quality evidence. Enablement requires recorded approval from both the **Application Security lead** (detection quality and false-positive risk) and the **Product Security owner** (customer impact and 70% portfolio target). The release owner may publish only the exact approved configuration version; they do not substitute for either approver. Approval records must name the rule ID, rule version, configuration version, evidence links, approvers, and timestamp.

Rule definitions live in immutable, versioned configuration files. `enabled: false` prevents that rule from producing findings in future scans but retains its definition and version. Never edit a released configuration in place: copy it to the next version, change the switch or rule metadata there, and retain prior files.

Existing findings are snapshots and are never deleted, rewritten, or silently reclassified by enablement changes. They retain their original `rule_id`, `rule_version`, evidence, scan pack version, and audit history. Disabling affects only scans using the newer configuration. Changing detection logic or user-visible meaning requires a new `rule_version`; a metadata-free enable/disable change requires only a new `configuration_version`. Re-enabling an unchanged rule may reuse its rule version. Reports must group results by both rule ID and rule version, and users may explicitly rescan a repository to obtain results under a newer version.

## Quality-report source

`analyzer/regression/pilot_reviews.json` is the review-level source of truth. Outcomes are mutually exclusive. `analyzer.quality.summarize_reviews` validates outcomes and computes the report; duplicates and needs-context decisions are not counted as accepted. Amendments require a new `review_version`, reviewer traceability in the controlled review system, regeneration of the report, and review alongside the configuration promotion record.
