# Pilot baseline

This directory contains the controlled procedure for establishing a pilot baseline without
committing customer source, evidence, identifiers, or other sensitive data.

- [Baseline procedure](baseline-procedure.md) defines the cohort, golden path, measurements,
  review protocol, privacy checks, and exit criteria.
- [Baseline results](baseline-results.md) is the aggregate-only record to copy for each executed
  baseline run. It deliberately contains no fabricated run.
- [Follow-up defects](follow-up-defects.md) records prioritized golden-path blockers. Add a defect
  during triage whenever a run cannot finish a required step.

The baseline owner must update the results record and defect register in the same change after a
run. A repository is not evidence that a baseline was executed: the results record must name the
environment class, release, time window, and aggregate cohort size.
