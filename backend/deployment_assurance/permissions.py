"""Permission identifiers for Deployment Assurance.

Extends the existing ``core.security`` RBAC vocabulary rather than introducing a
second authorization system. Two boundaries are load-bearing:

* **Machines submit; humans decide.** A CI service account can submit a
  snapshot, request an evaluation and read the decision. It cannot approve a
  waiver, accept risk, or execute remediation. This mirrors the platform's
  existing prohibition on service-account risk acceptance.
* **Requesting is not approving.** ``deployment_exception.request`` and
  ``deployment_exception.approve`` are separate grants, and the viewset
  additionally refuses self-approval, so holding both roles still does not let
  one person wave through their own exception.
"""

TARGET_READ = "deployment_target.read"
TARGET_WRITE = "deployment_target.write"
SNAPSHOT_SUBMIT = "deployment_snapshot.submit"
SNAPSHOT_READ = "deployment_snapshot.read"
EVALUATION_CREATE = "deployment_evaluation.create"
EVALUATION_READ = "deployment_evaluation.read"
DECISION_READ = "deployment_decision.read"
EXCEPTION_REQUEST = "deployment_exception.request"
EXCEPTION_APPROVE = "deployment_exception.approve"
POLICY_READ = "deployment_policy.read"
POLICY_MANAGE = "deployment_policy.manage"
EVIDENCE_READ = "deployment_evidence.read"
DRIFT_READ = "deployment_drift.read"

ALL_PERMISSIONS = frozenset(
    {
        TARGET_READ,
        TARGET_WRITE,
        SNAPSHOT_SUBMIT,
        SNAPSHOT_READ,
        EVALUATION_CREATE,
        EVALUATION_READ,
        DECISION_READ,
        EXCEPTION_REQUEST,
        EXCEPTION_APPROVE,
        POLICY_READ,
        POLICY_MANAGE,
        EVIDENCE_READ,
        DRIFT_READ,
    }
)

#: Read-only visibility, granted to every role that can already see risk.
READ_ONLY_BUNDLE = frozenset({TARGET_READ, SNAPSHOT_READ, EVALUATION_READ, DECISION_READ, POLICY_READ, DRIFT_READ})

#: Additional grants per existing ``core.models.Membership.Role``.
ROLE_GRANTS = {
    "org_admin": READ_ONLY_BUNDLE | {TARGET_WRITE, SNAPSHOT_SUBMIT, EVALUATION_CREATE, EVIDENCE_READ},
    "compliance_manager": READ_ONLY_BUNDLE
    | {TARGET_WRITE, SNAPSHOT_SUBMIT, EVALUATION_CREATE, EXCEPTION_REQUEST, EVIDENCE_READ},
    "control_owner": {TARGET_READ, SNAPSHOT_READ, EVALUATION_READ, DECISION_READ},
    "ciso": READ_ONLY_BUNDLE | {EXCEPTION_APPROVE, EVIDENCE_READ},
    "architect": READ_ONLY_BUNDLE | {TARGET_WRITE},
    "appsec": READ_ONLY_BUNDLE | {TARGET_WRITE, SNAPSHOT_SUBMIT, EVALUATION_CREATE, EXCEPTION_REQUEST, EVIDENCE_READ},
    "assessor": READ_ONLY_BUNDLE | {EVIDENCE_READ},
    "developer": {TARGET_READ, SNAPSHOT_SUBMIT, SNAPSHOT_READ, EVALUATION_CREATE, EVALUATION_READ, DECISION_READ},
    "manager": READ_ONLY_BUNDLE | {EXCEPTION_REQUEST},
    "auditor": READ_ONLY_BUNDLE | {EVIDENCE_READ},
    "executive": {TARGET_READ, DECISION_READ, DRIFT_READ},
}

#: Permissions a service account may never hold, regardless of issued scopes.
#: Enforced in the viewsets, not merely at token issuance.
HUMAN_ONLY = frozenset({EXCEPTION_APPROVE, EXCEPTION_REQUEST, POLICY_MANAGE})
