PERSONAS = (
    ("dev-platform-admin", "Platform admin", "platform_admin", "dev-platform"),
    ("dev-firm-admin", "Firm admin", "firm_admin", "dev-firm"),
    ("dev-audit-manager", "Audit manager", "audit_manager", "dev-firm"),
    ("dev-auditor", "Auditor", "auditor", "dev-firm"),
    ("dev-org-admin", "Organisation admin", "org_admin", "dev-auditee"),
    ("dev-compliance-manager", "Compliance manager", "compliance_manager", "dev-auditee"),
    ("dev-control-owner", "Control owner", "control_owner", "dev-auditee"),
    ("dev-risk-owner", "Risk owner", "risk_owner", "dev-auditee"),
    ("dev-ciso", "CISO", "ciso", "dev-auditee"),
)

PERSONA_USERNAMES = {username for username, _, _, _ in PERSONAS}
