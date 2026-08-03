# ADR-0001: Improve Python detection quality after the pilot

- **Status:** Accepted
- **Decision date:** 2026-08-03
- **Decision horizon:** One quarter after the pilot
- **Owner:** Product and detection engineering

## Context

The pilot has one experimental detection pack and two competing expansion requests: add the
most-requested second language or turn the existing Kubernetes/OpenShift profile into a fully
supported product. This record chooses exactly one primary investment for the next quarter.

This is a repository-informed decision, not a substitute for pilot research. No structured
reviewer-request log, customer repository census, baseline precision/recall report, or deployment
support data is committed in this repository. Consequently, “most-requested” identifies the
leading second-language request but does not establish which language it is or how large the lead
is. Product must preserve the underlying request counts and language mix before implementation.

## Evidence and assumptions

The available evidence favors closing the quality gap in the capability already presented to
pilot reviewers:

- The product describes the Python pack as experimental until representative customer
  repositories establish precision, recall, framework coverage, and maintenance acceptance.
- The analyzer supports only Python, exposes just three deterministic AST rules, counts parse
  failures and unsupported files, and labels its coverage `experimental`.
- The analyzer has one focused regression test. This makes the quality gap visible and a
  one-quarter measurement plan practical, but it is not evidence that current detection quality
  is acceptable.
- Repository composition is strongly Python-oriented: at the decision date, the tracked tree has
  48 `.py` files and 4,665 lines of Python, versus 7 `.ts`/`.tsx` files and 273 lines of
  TypeScript/TSX. Composition is implementation evidence, not customer-language demand; it lowers
  the cost of improving Python but must not be used to infer the second language.
- Kubernetes already has a Kustomize base, OpenShift overlay, restricted pod security, network
  policies, RBAC, autoscaling, disruption budgets, an installer, native isolated analyzer jobs,
  and deployment documentation. However, operations explicitly names Compose as the supported MVP
  and Kubernetes/OpenShift as a later profile. Productizing it would add a substantial support and
  compatibility surface rather than merely finishing a manifest.
- Kubernetes analysis deliberately adds privileged control-plane interactions, scratch PVCs,
  presigned transfer URLs, external egress policy, customer-managed dependencies, and cluster
  version/CSI/ingress variation. Existing fail-closed controls are a strong foundation, but the
  operational and security validation burden is higher than for detection-only work.

Assumptions to validate during pilot closeout are that Python repositories are sufficiently common
to make quality improvements useful, reviewers experience trust or coverage pain with the current
pack, and Kubernetes is not a pilot-blocking procurement requirement. If any assumption is false,
use the reconsideration triggers below rather than silently changing priorities.

## Scoring method

Each criterion is equally weighted and scored from **1 (unfavorable)** to **5 (favorable)**. For
engineering effort and operational burden, a higher score means lower total burden. For security
impact, a higher score means lower added attack surface and/or a clearer reduction in customer
risk. A total is a decision aid, not invented precision; uncertain demand scores are deliberately
conservative because the repository contains no request log.

| Criterion | Improve Python detection quality | Add demand-leading second language | Productize Kubernetes deployment |
| --- | ---: | ---: | ---: |
| Pilot reviewer demand | **4** — directly improves the only review pack, subject to validating pilot feedback | **5** — explicitly the leading expansion request, but volume and language are unrecorded | **2** — no committed evidence that reviewers require it |
| Unresolved user pain | **5** — experimental precision, recall, framework coverage, and trust are explicit gaps | **3** — expands eligibility but leaves detection-quality pain unresolved | **2** — helps enterprise operators, while a supported Compose path already exists |
| Expected customer value | **5** — improves trust and usefulness for every supported scan | **4** — unlocks a cohort using another language, with value dependent on its share | **3** — valuable where Kubernetes is mandatory, limited elsewhere |
| Engineering effort and operational burden | **4** — extends one AST pipeline and test harness; rule research remains material | **2** — requires a new parser, rule corpus, fixtures, packaging, and ongoing maintenance | **1** — creates a cluster compatibility, upgrade, observability, and support matrix |
| Security impact | **5** — better detection can reduce missed vulnerabilities without adding runtime privilege | **4** — similar isolated execution model, but a new parser and rules add supply-chain and false-negative risk | **2** — controls are strong, but cluster API, PVC, URL-transfer, egress, and secret integrations enlarge assurance scope |
| Repository and deployment evidence | **5** — sole installed pack, explicit experimental label, three rules, Python-heavy implementation | **2** — architecture can host packs, but no second-language implementation or reliable demand identity exists | **4** — substantial profile exists, while documentation explicitly defers support |
| Measurable in one quarter | **5** — blinded precision/recall, coverage, parse success, and reviewer disposition are observable | **3** — adoption and basic accuracy are measurable, but representative corpus creation competes with implementation | **2** — install success can be measured, but meaningful compatibility and operational evidence needs multiple customer environments |
| **Total / 35** | **33** | **23** | **16** |

## Decision

**The sole primary investment for the quarter after the pilot is improving Python detection
quality.** No capacity from this investment is allocated to a second production language or to a
supported Kubernetes product during the decision horizon. Maintenance and critical security fixes
remain obligations, not competing feature investments.

The investment includes:

1. Build a consented, representative, versioned Python evaluation corpus stratified by framework
   and vulnerability class, with a held-out blind set and explicit expected findings.
2. Record the baseline before changing rules: file parse success, eligible-code coverage,
   finding-level precision and recall, duplicate rate, and reviewer dispositions.
3. Improve framework-aware and data-flow-sensitive detections selected from observed pilot false
   positives and false negatives; do not optimize only for the existing three-rule fixture.
4. Add regression fixtures for positive, negative, aliased-import, syntax-version, and framework
   cases. Every finding must remain deterministic, evidence-backed, and `needs_validation` until a
   human disposition.
5. Instrument privacy-preserving aggregate scan coverage and reviewer disposition outcomes, with
   tenant controls and no source, snippets, secrets, or customer identifiers in telemetry.

### One-quarter success measures

Before work starts, the owner records corpus inclusion rules, sample sizes, framework strata, and
baseline values. The quarter succeeds only if all of the following are reported for both the
overall corpus and every material stratum:

- At least **90% precision** and **70% recall** on the held-out set, with 95% confidence intervals
  and no regression from baseline in either metric. These are decision thresholds, not claims
  about current performance.
- At least **99% parse success** for eligible Python files; unsupported and excluded files remain
  separately reported rather than being counted as successful.
- At least **80% of pilot Python repositories** meet the predeclared eligible-code coverage target;
  the target itself is fixed after the pilot census and before rule development.
- At least **70% reviewer disposition completion** for surfaced findings and a median disposition
  time no worse than baseline, so accuracy is paired with workflow usability.
- Zero confirmed cross-tenant evidence exposure, raw-source telemetry events, or analyzer isolation
  regressions in the release candidate.

If the representative corpus or baseline cannot be established by the end of week three, the
investment does not claim success; product reconvenes this decision with the missing evidence.

## Rejected alternatives and reconsideration triggers

### Add the most-requested second language

Rejected for this quarter because breadth would reproduce an unproven quality model, split the
evaluation effort, and leave trust in the current pack unresolved. Repository composition cannot
identify customer demand, and the actual requested language is not recorded here.

Reconsider when **all** of these are true:

- the pilot request log and repository census identify the same leading language, with at least
  **30% of otherwise-qualified pilot repositories** blocked by its absence;
- the Python quarter meets its precision, recall, coverage, and reviewer-workflow gates; and
- a representative labeled corpus, parser/sandbox threat model, named maintenance owner, and
  one-quarter delivery estimate exist for that language.

### Productize Kubernetes deployment

Rejected for this quarter because Compose is the supported MVP, while a supported orchestration
product would create a large security, compatibility, and operational obligation. Existing
manifests demonstrate feasibility but not repeatable operation across customer clusters.

Reconsider immediately if a signed pilot conversion is blocked on Kubernetes/OpenShift or
customer policy prohibits the supported Compose topology. Otherwise reconsider when at least
**two target customers on distinct supported cluster distributions** commit to acceptance testing,
and the team has defined a bounded version/CSI/ingress matrix, upgrade and rollback SLOs, support
ownership, penetration-test scope, and a successful restore exercise in each reference environment.

## Ranked post-pilot feature backlog

This backlog is the single destination for feature requests outside the selected investment during
the decision horizon. Rank does not authorize implementation. Critical defects, dependency
updates, and security remediation follow the maintenance process and are not feature requests.

1. **Demand-leading second-language pack.** First because it has the clearest stated expansion
   demand. Confirm the language from preserved request counts; meet the trigger and apply the same
   corpus, accuracy, evidence, isolation, and ownership gates as Python.
2. **Supported Kubernetes/OpenShift product.** Second because much of the technical profile exists,
   but promote it only after the customer and support-matrix trigger demonstrates that its ongoing
   operational burden produces conversion value.

New feature requests discovered during the pilot must be recorded with requester count, blocked
workflow, affected customer/repository share, security impact, estimated build and run cost, and a
one-quarter success measure. Product ranks them against the two items above at the next formal
review; they do not enter the active quarter by default.

## Consequences

- The product favors depth and reviewer trust over language breadth and deployment breadth for one
  quarter.
- Prospects needing another language or a supported Kubernetes topology may remain blocked; sales
  and product must record those losses rather than promise unplanned delivery.
- Accuracy claims become auditable against a versioned corpus and explicit denominators.
- Kubernetes artifacts remain an enterprise **profile**, not a supported MVP deployment, until its
  trigger is met and a later decision changes that status.
