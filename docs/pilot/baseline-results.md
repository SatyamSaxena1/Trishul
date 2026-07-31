# Pilot baseline aggregate results

## Run status

**No baseline run has been executed or claimed by this document.** Copy the template below to a
dated section after following the procedure. Replace every `TBD`; do not enter repository, tenant,
application, user, job, scan, finding, or risk identifiers. Do not enter source paths, snippets,
finding text, raw errors, timestamps precise enough to identify a person, or links to restricted
evidence.

## Run template

### Context

| Field | Aggregate value |
| --- | --- |
| Run label | TBD (non-sensitive) |
| UTC date range | TBD (dates only) |
| Release / analyzer digest / pack version | TBD |
| Deployment class and configured concurrency | TBD |
| Cohort | synthetic: TBD; representative: TBD; negative controls: TBD; other: TBD |
| Pilot decision | TBD (`go`, `conditional`, or `no-go`) |

### Job flow and runtime

| Metric | Aggregate value |
| --- | ---: |
| Submissions attempted | TBD |
| Rejected before job creation | TBD |
| Total jobs submitted (accepted) | TBD |
| Completed jobs | TBD |
| Failed jobs | TBD |
| Cancelled jobs | TBD |
| Still non-terminal at cutoff | TBD |
| Stuck jobs | TBD |
| Manually recovered jobs | TBD |

Runtime population: TBD completed jobs; units: seconds; start: accepted/queued observation; end:
terminal observation; percentile method: nearest-rank.

| Minimum | p50 | p90 | p95 | Maximum | Mean |
| ---: | ---: | ---: | ---: | ---: | ---: |
| TBD | TBD | TBD | TBD | TBD | TBD |

Rejected counts by aggregate validation category and failed counts by sanitized error class:

| Category/class | Rejected | Failed |
| --- | ---: | ---: |
| TBD | TBD | TBD |

### Findings and analyst review

| Rule ID (or `other`) | Emitted | Confirmed | False positive | Needs validation | Other terminal outcome |
| --- | ---: | ---: | ---: | ---: | ---: |
| TBD | TBD | TBD | TBD | TBD | TBD |
| **Total** | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** |

| Observation | Aggregate value |
| --- | ---: |
| Findings reviewed | TBD |
| Unreviewed candidates | TBD |
| False-positive rate among reviewed | TBD |
| Duplicate fingerprints within a scan | TBD |
| Stable matches on identical resubmission | TBD |
| Missing matches on identical resubmission | TBD |
| Unexpected additional matches on identical resubmission | TBD |
| Synthetic oracle true positives (if measured) | TBD / not measured |
| Synthetic oracle false negatives (if measured) | TBD / not measured |

### Risk outcomes

| Outcome for confirmed findings | Aggregate count |
| --- | ---: |
| Scored risks created | TBD |
| Remediation created | TBD |
| Acceptance approved | TBD |
| Acceptance rejected | TBD |
| Open/undecided | TBD |

### Recovery, blockers, and manual work

| Recovery action category | Jobs affected |
| --- | ---: |
| TBD / none | TBD |

| Defect ID | Priority | Blocked step | Jobs affected | Workaround category |
| --- | --- | --- | ---: | --- |
| TBD / none | TBD | TBD | TBD | TBD |

| Manual-step category | Occurrences | Operator time (minutes) |
| --- | ---: | ---: |
| Repository/API setup | TBD | TBD |
| Polling/measurement | TBD | TBD |
| Finding review | TBD | TBD |
| Risk creation/disposition | TBD | TBD |
| Recovery | TBD | TBD |
| Other | TBD | TBD |

Aggregate notes (no names, identifiers, source/evidence content, or raw errors): TBD.

### Reconciliation and approval

- [ ] `submitted = completed + failed + cancelled + still non-terminal`.
- [ ] Finding rule totals equal analyst outcome totals plus unreviewed candidates.
- [ ] Confirmed-finding risk outcomes reconcile, with exceptions explained in aggregate notes.
- [ ] Every blocker appears in the follow-up defect register.
- [ ] Pilot owner and analyst signed the restricted record.
- [ ] A reviewer confirmed this committed section contains only aggregate, non-sensitive data.
