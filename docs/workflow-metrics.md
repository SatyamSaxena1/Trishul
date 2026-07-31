# Repository workflow measurements

Trishul records UTC database timestamps at the repository and scan boundaries. Submission and archive-validation
timestamps belong to the immutable repository version. Queueing, execution, persistence, analyst review, and optional
risk completion timestamps belong to the tenant-scoped scan. A first review is the first transition of any finding to
`confirmed`, `false_positive`, or `resolved`; final review is recorded once every finding in that scan has reached one
of those outcomes. Risk completion is recorded only when a finding-linked risk becomes `accepted`, `mitigated`, or
`closed`, or its acceptance receives a final decision.

`/api/v1/metrics` publishes only cross-tenant aggregates. Its labels are fixed enums (`stage`, `workflow`, `stat`,
`outcome`, and `result`); tenant IDs, repository IDs or names, paths, evidence, prompts, credentials, and user data are
never labels. Access remains protected by `X-Metrics-Token`.

## Formulas

- **Completion rate** = analyses with outcome `completed` / analyses with outcome `completed` or `failed`. Queued or
  currently running analyses are excluded. Return “not available” rather than zero when the denominator is zero.
- **Runtime percentiles**: for each completed start/termination pair, runtime = `analysis_terminated_at -
  analysis_started_at`. Sort runtimes and use linearly interpolated ranks `(n - 1) × q` for p50, p90, p95, and p99.
  The endpoint also exposes the sample count and sum.
- **Recovery rate** = jobs completed with `attempts > 1` / all jobs with `attempts > 1`. Jobs never retried are excluded;
  return “not available” when no retry has occurred.
- **Analyst usefulness** = confirmed findings / (`confirmed` + `false_positive`) findings. `candidate`,
  `needs_validation`, and unresolved findings are excluded because they do not yet express an analyst judgment. Return
  “not available” when no analyst judgment exists.

Suggested PromQL (guard denominators in dashboards):

```promql
# Completion rate
trishul_analysis_outcome_total{outcome="completed"}
/
sum(trishul_analysis_outcome_total)

# Recovery rate
trishul_analysis_recovery_total{result="recovered"}
/
trishul_analysis_recovery_total{result="retried"}

# Analyst usefulness
trishul_finding_review_outcome_total{outcome="confirmed"}
/
sum(trishul_finding_review_outcome_total{outcome=~"confirmed|false_positive"})
```
