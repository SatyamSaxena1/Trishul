"""``trishul-baseline`` v1.0.0 — the shipped control pack.

Twenty rules covering the failure modes that most often turn into a real
incident: exposed administrative and database ports, unencrypted data at rest,
committed credentials, exploitable vulnerabilities, unsupported operating
systems, absent audit logging, over-broad identity grants and unsafe container
configuration.

Two conventions run through the pack:

* **Environment-aware severity, not environment-aware truth.** A rule reports
  the same fact everywhere; only the consequence (block versus warn) varies with
  environment and exposure, and only via ``context.target``.
* **Unknown is not pass.** Where an artifact does not carry enough information
  to judge — an opaque IAM document, a missing encryption attribute on a
  provider that has no default — the rule returns ``manual_review``.

The framework identifiers in ``mappings`` are *control traceability*: this rule
produces evidence relevant to that control. They are not an assertion that
passing the rule satisfies the control, and they must be reviewed against the
exact framework editions a customer has adopted.
"""

from typing import Sequence

from ...resources import Resource, ResourceType
from ..sdk import FAIL, MANUAL_REVIEW, NOT_APPLICABLE, PASS, WARNING, ResourceRule, RuleContext, RuleResult

PACK_KEY = "trishul-baseline"
PACK_VERSION = "1.0.0"
PACK_TITLE = "Trishul baseline deployment controls"
PACK_DESCRIPTION = (
    "Deterministic pre-deployment and live-state controls for cloud, Kubernetes, Compose and on-premises targets."
)

UNRESTRICTED = frozenset({"0.0.0.0/0", "::/0", "*", "any", "internet"})


def _unrestricted_sources(resource: Resource) -> list[str]:
    return sorted({str(item) for item in resource.attribute("source_cidrs", ()) if str(item).lower() in UNRESTRICTED})


def _matching_ports(resource: Resource, wanted: Sequence[int]) -> list[int]:
    ports = {int(port) for port in resource.attribute("ports", ()) if isinstance(port, (int, float))}
    return sorted(ports & set(wanted))


class PublicAdminPort(ResourceRule):
    rule_id = "DA-NET-001"
    title = "Administrative ports are not reachable from unrestricted networks"
    description = (
        "SSH, RDP and WinRM must not accept connections from 0.0.0.0/0 or ::/0. "
        "Administrative access belongs behind an approved management network, "
        "bastion or identity-aware proxy."
    )
    category = "network"
    severity = 5
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.INGRESS_RULE,)
    remediation = (
        "Replace the unrestricted source range with the approved management CIDRs, "
        "or remove the rule and reach the host through the bastion or identity-aware proxy."
    )
    default_parameters = {"administrative_ports": [22, 3389, 5985, 5986], "approved_management_cidrs": []}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AC-17"),
        ("NIST SP 800-53", "Rev. 5", "SC-7"),
        ("NIST SP 800-53", "Rev. 5", "CM-7"),
        ("CIS Controls", "v8.1", "4.4"),
        ("CIS Controls", "v8.1", "12.2"),
        ("ISO/IEC 27002", "2022", "A.8.20"),
        ("PCI DSS", "v4.0.1", "1"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        ports = _matching_ports(resource, context.parameter("administrative_ports", []))
        if not ports:
            return (RuleResult(NOT_APPLICABLE, "NOT_ADMIN_PORT", "No administrative port is exposed by this rule."),)
        unrestricted = _unrestricted_sources(resource)
        if not unrestricted:
            return (
                RuleResult(
                    PASS,
                    "ADMIN_ACCESS_RESTRICTED",
                    "Administrative access is restricted to specific source ranges.",
                    observed={"ports": ports, "source_cidrs": list(resource.attribute("source_cidrs", ()))},
                ),
            )
        return (
            RuleResult(
                FAIL,
                "PUBLIC_ADMIN_PORT",
                f"Administrative port(s) {ports} accept connections from {', '.join(unrestricted)}.",
                observed={"ports": ports, "unrestricted_sources": unrestricted},
                expected={"source_cidrs": list(context.parameter("approved_management_cidrs", []))},
            ),
        )


class PublicDatabasePort(ResourceRule):
    rule_id = "DA-NET-002"
    title = "Database ports are not reachable from unrestricted networks"
    description = "Database listeners must not be exposed directly to the internet."
    category = "network"
    severity = 5
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.INGRESS_RULE, ResourceType.DATABASE_INSTANCE)
    remediation = (
        "Restrict the security group or firewall rule to application subnets, and disable "
        "public accessibility on the managed database instance."
    )
    default_parameters = {"database_ports": [1433, 1521, 3306, 5432, 6379, 9200, 27017]}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "SC-7"),
        ("NIST SP 800-53", "Rev. 5", "AC-4"),
        ("CIS Controls", "v8.1", "4.4"),
        ("ISO/IEC 27002", "2022", "A.8.22"),
        ("PCI DSS", "v4.0.1", "1"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if resource.resource_type == ResourceType.DATABASE_INSTANCE:
            if not resource.attribute("publicly_accessible"):
                return (RuleResult(PASS, "DATABASE_NOT_PUBLIC", "The database instance is not publicly accessible."),)
            return (
                RuleResult(
                    FAIL,
                    "PUBLIC_DATABASE_INSTANCE",
                    "The managed database instance is marked publicly accessible.",
                    observed={"publicly_accessible": True},
                    expected={"publicly_accessible": False},
                ),
            )
        ports = _matching_ports(resource, context.parameter("database_ports", []))
        if not ports:
            return (RuleResult(NOT_APPLICABLE, "NOT_DATABASE_PORT", "No database port is exposed by this rule."),)
        unrestricted = _unrestricted_sources(resource)
        if not unrestricted:
            return (RuleResult(PASS, "DATABASE_ACCESS_RESTRICTED", "Database access is restricted."),)
        return (
            RuleResult(
                FAIL,
                "PUBLIC_DATABASE_PORT",
                f"Database port(s) {ports} accept connections from {', '.join(unrestricted)}.",
                observed={"ports": ports, "unrestricted_sources": unrestricted},
                expected={"source_cidrs": ["application subnets only"]},
            ),
        )


class EncryptionAtRest(ResourceRule):
    rule_id = "DA-ENC-001"
    title = "Storage holding sensitive data is encrypted at rest"
    description = "Buckets, volumes and databases carrying sensitive data must use approved encryption at rest."
    category = "encryption"
    severity = 4
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.STORAGE_BUCKET, ResourceType.STORAGE_VOLUME, ResourceType.DATABASE_INSTANCE)
    remediation = "Enable server-side encryption with a managed or customer-managed key and re-apply."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "SC-13"),
        ("NIST SP 800-53", "Rev. 5", "SC-28"),
        ("CIS Controls", "v8.1", "3.11"),
        ("ISO/IEC 27002", "2022", "A.8.24"),
        ("PCI DSS", "v4.0.1", "3"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if not resource.attribute("holds_sensitive_data", True):
            return (
                RuleResult(NOT_APPLICABLE, "NO_SENSITIVE_DATA", "Resource is not marked as holding sensitive data."),
            )
        encrypted = resource.attribute("encrypted")
        if encrypted is None:
            return (
                RuleResult(
                    MANUAL_REVIEW,
                    "ENCRYPTION_UNKNOWN",
                    "The artifact does not state whether this store is encrypted; confirm manually.",
                    confidence=2,
                ),
            )
        if encrypted:
            return (RuleResult(PASS, "ENCRYPTED_AT_REST", "Encryption at rest is enabled."),)
        return (
            RuleResult(
                FAIL,
                "UNENCRYPTED_AT_REST",
                "Sensitive storage is provisioned without encryption at rest.",
                observed={"encrypted": False},
                expected={"encrypted": True},
            ),
        )


class PublicObjectStorage(ResourceRule):
    rule_id = "DA-STOR-001"
    title = "Object storage does not permit public access"
    description = "Buckets must block public access unless an approved exception documents a public-content purpose."
    category = "configuration"
    severity = 4
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.STORAGE_BUCKET,)
    remediation = "Enable the provider's block-public-access control and remove public ACL grants."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AC-3"),
        ("NIST SP 800-53", "Rev. 5", "SC-7"),
        ("CIS Controls", "v8.1", "3.3"),
        ("ISO/IEC 27002", "2022", "A.8.3"),
        ("PCI DSS", "v4.0.1", "7"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        acl = str(resource.attribute("acl", "private")).lower()
        blocked = resource.attribute("public_access_blocked", True)
        if blocked and "public" not in acl:
            return (RuleResult(PASS, "PUBLIC_ACCESS_BLOCKED", "Public access is blocked."),)
        return (
            RuleResult(
                FAIL,
                "PUBLIC_OBJECT_STORAGE",
                "The bucket permits public access.",
                observed={"public_access_blocked": bool(blocked), "acl": acl},
                expected={"public_access_blocked": True, "acl": "private"},
            ),
        )


class PlaintextSecret(ResourceRule):
    rule_id = "DA-SEC-001"
    title = "No plaintext secret is embedded in the deployment artifact"
    description = (
        "Credentials must be supplied through a secrets manager or mounted secret reference, "
        "never committed in a plan, manifest or Compose file."
    )
    category = "identity"
    severity = 5
    blocking = True
    automation_class = "guidance"
    resource_types = (ResourceType.SECRET_MATERIAL,)
    remediation = (
        "Remove the literal value, rotate the exposed credential, and reference it through the "
        "platform secrets manager or a mounted secret."
    )
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "IA-5"),
        ("NIST SP 800-53", "Rev. 5", "SC-12"),
        ("CIS Controls", "v8.1", "3.11"),
        ("ISO/IEC 27002", "2022", "A.8.24"),
        ("PCI DSS", "v4.0.1", "8"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        reasons = list(resource.attribute("detection_reasons", ()))
        return (
            RuleResult(
                FAIL,
                "PLAINTEXT_SECRET_PRESENT",
                (
                    f"Credential material was detected at {resource.attribute('attribute_path', resource.resource_id)} "
                    f"({', '.join(reasons) or 'unclassified'}). The value is not recorded in evidence."
                ),
                # Digest only. The detector never propagates the matched value.
                observed={
                    "attribute_path": resource.attribute("attribute_path", ""),
                    "detection_reasons": reasons,
                    "value_sha256": resource.attribute("value_sha256", ""),
                },
                expected={"source": "secrets manager reference"},
            ),
        )


class CriticalVulnerability(ResourceRule):
    rule_id = "DA-VULN-001"
    title = "No unwaived critical vulnerability is present"
    description = "A vulnerability at or above the critical CVSS threshold blocks deployment until fixed or waived."
    category = "vulnerability"
    severity = 5
    blocking = True
    automation_class = "guidance"
    resource_types = (ResourceType.VULNERABILITY,)
    remediation = "Apply the vendor fix or upgrade the affected component, then re-run the evaluation."
    default_parameters = {"critical_cvss": 9.0, "high_cvss": 7.0}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "RA-5"),
        ("NIST SP 800-53", "Rev. 5", "SI-2"),
        ("CIS Controls", "v8.1", "7.1"),
        ("ISO/IEC 27002", "2022", "A.8.8"),
        ("PCI DSS", "v4.0.1", "6"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        cvss = float(resource.attribute("cvss", 0.0) or 0.0)
        critical = float(context.parameter("critical_cvss", 9.0))
        high = float(context.parameter("high_cvss", 7.0))
        identifier = resource.attribute("cve") or resource.resource_id
        observed = {
            "cve": resource.attribute("cve", ""),
            "cvss": cvss,
            "exploit_known": bool(resource.attribute("exploit_known")),
            "asset_id": resource.attribute("asset_id", ""),
        }
        if cvss >= critical or (resource.attribute("exploit_known") and cvss >= high):
            return (
                RuleResult(
                    FAIL,
                    "CRITICAL_VULNERABILITY",
                    f"{identifier} scores {cvss} and is exploitable in this deployment.",
                    observed=observed,
                    expected={"cvss_below": critical},
                ),
            )
        if cvss >= high:
            return (
                RuleResult(
                    WARNING,
                    "HIGH_VULNERABILITY",
                    f"{identifier} scores {cvss}; schedule remediation.",
                    observed=observed,
                    severity=3,
                ),
            )
        return (RuleResult(PASS, "VULNERABILITY_BELOW_THRESHOLD", f"{identifier} is below the action threshold."),)


class UnsupportedOperatingSystem(ResourceRule):
    rule_id = "DA-OS-001"
    title = "Hosts run a vendor-supported operating system"
    description = "An operating system past vendor end-of-support cannot receive security fixes."
    category = "configuration"
    severity = 4
    blocking = True
    automation_class = "guidance"
    resource_types = (ResourceType.OS_HOST,)
    remediation = "Upgrade to a supported release, or move the workload to a supported base image."
    # Configurable, never hard-coded: customers with extended-support contracts
    # legitimately run releases that are otherwise end-of-life.
    default_parameters = {
        "minimum_supported_versions": {"ubuntu": "22.04", "debian": "12", "rhel": "8", "centos": "9", "windows": "2019"}
    }
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "SI-2"),
        ("NIST SP 800-53", "Rev. 5", "CM-6"),
        ("CIS Controls", "v8.1", "2.2"),
        ("ISO/IEC 27002", "2022", "A.8.8"),
        ("PCI DSS", "v4.0.1", "6"),
    )

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, ...]:
        parts = []
        for chunk in str(value).replace("-", ".").split("."):
            digits = "".join(character for character in chunk if character.isdigit())
            if digits:
                parts.append(int(digits))
        return tuple(parts) or (0,)

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        minimums = context.parameter("minimum_supported_versions", {}) or {}
        os_name = str(resource.attribute("os_name", "")).lower()
        os_version = str(resource.attribute("os_version", ""))
        if os_name not in minimums:
            return (
                RuleResult(
                    MANUAL_REVIEW,
                    "OS_SUPPORT_UNKNOWN",
                    f"No support baseline is configured for operating system {os_name or 'unknown'!r}.",
                    observed={"os_name": os_name, "os_version": os_version},
                    confidence=2,
                ),
            )
        minimum = str(minimums[os_name])
        if self._version_tuple(os_version) >= self._version_tuple(minimum):
            return (RuleResult(PASS, "OS_SUPPORTED", f"{os_name} {os_version} is within the supported baseline."),)
        return (
            RuleResult(
                FAIL,
                "OS_UNSUPPORTED",
                f"{os_name} {os_version} is below the supported baseline of {minimum}.",
                observed={"os_name": os_name, "os_version": os_version},
                expected={"minimum_version": minimum},
            ),
        )


class AuditLoggingEnabled(ResourceRule):
    rule_id = "DA-LOG-001"
    title = "Administrative and configuration events are logged"
    description = "Audit logging must be enabled for production targets."
    category = "logging"
    severity = 4
    blocking = True
    automation_class = "approval_required"
    resource_types = (ResourceType.LOGGING_SINK,)
    remediation = "Enable the audit trail and confirm it is delivering to the retained destination."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AU-2"),
        ("NIST SP 800-53", "Rev. 5", "AU-12"),
        ("CIS Controls", "v8.1", "8.2"),
        ("ISO/IEC 27002", "2022", "A.8.15"),
        ("PCI DSS", "v4.0.1", "10"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if resource.attribute("enabled", True):
            return (RuleResult(PASS, "AUDIT_LOGGING_ENABLED", "Audit logging is enabled."),)
        return (
            RuleResult(
                FAIL,
                "AUDIT_LOGGING_DISABLED",
                "The audit trail is provisioned but disabled.",
                observed={"enabled": False},
                expected={"enabled": True},
            ),
        )


class CentralizedLogDestination(ResourceRule):
    rule_id = "DA-LOG-002"
    title = "Logs are delivered to a centralized, retained destination"
    description = "Local-only logs are lost with the host and cannot support investigation."
    category = "logging"
    severity = 3
    blocking = False
    automation_class = "patch"
    resource_types = (ResourceType.LOGGING_SINK,)
    remediation = "Configure a centralized destination and set retention to at least the configured minimum."
    default_parameters = {"minimum_retention_days": 365}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AU-6"),
        ("NIST SP 800-53", "Rev. 5", "AU-11"),
        ("CIS Controls", "v8.1", "8.9"),
        ("CIS Controls", "v8.1", "8.10"),
        ("ISO/IEC 27002", "2022", "A.8.15"),
        ("PCI DSS", "v4.0.1", "10"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        minimum = int(context.parameter("minimum_retention_days", 365))
        retention = int(resource.attribute("retention_days", 0) or 0)
        if not resource.attribute("centralized"):
            return (
                RuleResult(
                    FAIL if context.target.is_production else WARNING,
                    "LOGS_NOT_CENTRALIZED",
                    "No centralized log destination is configured for this sink.",
                    expected={"centralized": True},
                ),
            )
        if retention < minimum:
            return (
                RuleResult(
                    WARNING,
                    "LOG_RETENTION_BELOW_MINIMUM",
                    f"Log retention is {retention} days, below the required {minimum}.",
                    observed={"retention_days": retention},
                    expected={"retention_days": minimum},
                ),
            )
        return (RuleResult(PASS, "LOGS_CENTRALIZED", "Logs are centralized with sufficient retention."),)


class WildcardIdentityGrant(ResourceRule):
    rule_id = "DA-IAM-001"
    title = "Identity policies avoid wildcard administrative privilege"
    description = "A policy granting every action on every resource defeats least privilege."
    category = "identity"
    severity = 4
    blocking = True
    automation_class = "guidance"
    resource_types = (ResourceType.IDENTITY_POLICY,)
    remediation = "Replace the wildcard grant with the specific actions and resources the workload requires."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AC-2"),
        ("NIST SP 800-53", "Rev. 5", "AC-6"),
        ("CIS Controls", "v8.1", "5.4"),
        ("CIS Controls", "v8.1", "6.8"),
        ("ISO/IEC 27002", "2022", "A.8.2"),
        ("PCI DSS", "v4.0.1", "7"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if not resource.attribute("document_parsed", True):
            return (
                RuleResult(
                    MANUAL_REVIEW,
                    "POLICY_DOCUMENT_OPAQUE",
                    "The policy document could not be parsed from the artifact; review it manually.",
                    confidence=1,
                ),
            )
        wildcard_actions = bool(resource.attribute("wildcard_actions"))
        wildcard_resources = bool(resource.attribute("wildcard_resources"))
        if wildcard_actions and wildcard_resources:
            return (
                RuleResult(
                    FAIL,
                    "WILDCARD_ADMIN_GRANT",
                    "The policy allows all actions on all resources.",
                    observed={"wildcard_actions": True, "wildcard_resources": True},
                    expected={"wildcard_actions": False, "wildcard_resources": False},
                ),
            )
        if wildcard_actions or wildcard_resources:
            return (
                RuleResult(
                    WARNING,
                    "PARTIAL_WILDCARD_GRANT",
                    "The policy uses a wildcard for actions or resources.",
                    observed={"wildcard_actions": wildcard_actions, "wildcard_resources": wildcard_resources},
                    severity=3,
                ),
            )
        return (RuleResult(PASS, "LEAST_PRIVILEGE_GRANT", "The policy avoids wildcard grants."),)


class PrivilegedContainer(ResourceRule):
    rule_id = "DA-K8S-001"
    title = "Containers do not run privileged"
    description = "A privileged container has effectively unrestricted access to the host kernel."
    category = "configuration"
    severity = 5
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.CONTAINER,)
    remediation = "Remove privileged mode and grant only the specific capabilities the workload requires."
    default_parameters = {"dangerous_capabilities": ["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"]}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AC-6"),
        ("NIST SP 800-53", "Rev. 5", "CM-7"),
        ("CIS Controls", "v8.1", "4.1"),
        ("ISO/IEC 27002", "2022", "A.8.9"),
        ("PCI DSS", "v4.0.1", "2"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        dangerous = {str(item).upper() for item in context.parameter("dangerous_capabilities", [])}
        added = {str(item).upper() for item in resource.attribute("added_capabilities", ())}
        if resource.attribute("privileged"):
            return (
                RuleResult(
                    FAIL,
                    "PRIVILEGED_CONTAINER",
                    "The container runs in privileged mode.",
                    observed={"privileged": True},
                    expected={"privileged": False},
                ),
            )
        escalated = sorted(added & dangerous)
        if escalated:
            return (
                RuleResult(
                    FAIL,
                    "DANGEROUS_CAPABILITY",
                    f"The container adds host-equivalent capabilities: {', '.join(escalated)}.",
                    observed={"added_capabilities": sorted(added)},
                    expected={"added_capabilities": []},
                ),
            )
        return (RuleResult(PASS, "CONTAINER_NOT_PRIVILEGED", "The container is not privileged."),)


class HostNamespaceAccess(ResourceRule):
    rule_id = "DA-K8S-002"
    title = "Containers do not share host namespaces or mount sensitive host paths"
    description = "Host network, PID or IPC sharing and sensitive hostPath mounts break workload isolation."
    category = "configuration"
    severity = 4
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.CONTAINER,)
    remediation = "Remove host namespace sharing and replace hostPath mounts with a managed volume."
    default_parameters = {"sensitive_host_paths": ["/", "/etc", "/var/run/docker.sock", "/var/lib", "/root", "/proc"]}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "SC-39"),
        ("NIST SP 800-53", "Rev. 5", "CM-7"),
        ("CIS Controls", "v8.1", "4.1"),
        ("ISO/IEC 27002", "2022", "A.8.31"),
        ("PCI DSS", "v4.0.1", "2"),
    )

    @staticmethod
    def _is_sensitive(path: str, sensitive: set[str]) -> bool:
        """A mount is sensitive if it is, or lives beneath, a listed path.

        ``/`` is handled separately: every absolute path is beneath it, so
        treating it as a prefix would flag every hostPath mount.
        """
        normalized = path.rstrip("/") or "/"
        if normalized in sensitive:
            return True
        return any(entry != "/" and normalized.startswith(entry + "/") for entry in sensitive)

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        shared = sorted(
            name
            for name, attribute in (("network", "host_network"), ("pid", "host_pid"), ("ipc", "host_ipc"))
            if resource.attribute(attribute)
        )
        sensitive = {str(item).rstrip("/") or "/" for item in context.parameter("sensitive_host_paths", [])}
        risky_mounts = sorted(
            str(path) for path in resource.attribute("host_path_mounts", ()) if self._is_sensitive(str(path), sensitive)
        )
        if shared or risky_mounts:
            return (
                RuleResult(
                    FAIL,
                    "HOST_NAMESPACE_OR_PATH",
                    (
                        f"The container shares host namespaces {shared or 'none'} "
                        f"and mounts sensitive host paths {risky_mounts or 'none'}."
                    ),
                    observed={"shared_namespaces": shared, "sensitive_host_paths": risky_mounts},
                    expected={"shared_namespaces": [], "sensitive_host_paths": []},
                ),
            )
        return (RuleResult(PASS, "WORKLOAD_ISOLATED", "The container does not share host namespaces."),)


class ContainerRunsAsRoot(ResourceRule):
    rule_id = "DA-K8S-003"
    title = "Containers run as a non-root user"
    description = "Running as UID 0 removes a meaningful barrier between a container escape and host compromise."
    category = "configuration"
    severity = 3
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.CONTAINER,)
    remediation = "Set runAsNonRoot with an explicit non-zero runAsUser, or set a non-root USER in the image."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AC-6"),
        ("CIS Controls", "v8.1", "4.1"),
        ("ISO/IEC 27002", "2022", "A.8.2"),
        ("PCI DSS", "v4.0.1", "2"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if not resource.attribute("runs_as_root"):
            return (RuleResult(PASS, "CONTAINER_NON_ROOT", "The container runs as a non-root user."),)
        # Outside production this is a warning: the finding is identical, the
        # consequence is proportionate to the environment.
        outcome = FAIL if context.target.is_production else WARNING
        return (
            RuleResult(
                outcome,
                "CONTAINER_RUNS_AS_ROOT",
                "The container runs as root or does not declare a non-root user.",
                observed={"run_as_user": resource.attribute("run_as_user")},
                expected={"runs_as_root": False},
                severity=None if outcome == FAIL else 2,
            ),
        )


class ContainerResourceLimits(ResourceRule):
    rule_id = "DA-K8S-004"
    title = "Containers declare CPU and memory limits"
    description = "A container without limits can exhaust node resources and degrade unrelated workloads."
    category = "configuration"
    severity = 2
    blocking = False
    automation_class = "patch"
    resource_types = (ResourceType.CONTAINER,)
    remediation = "Declare both CPU and memory limits sized from observed usage."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "SC-6"),
        ("CIS Controls", "v8.1", "4.1"),
        ("ISO/IEC 27002", "2022", "A.8.6"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if resource.attribute("has_resource_limits"):
            return (RuleResult(PASS, "RESOURCE_LIMITS_SET", "CPU and memory limits are declared."),)
        return (
            RuleResult(
                WARNING,
                "RESOURCE_LIMITS_MISSING",
                "The container does not declare both CPU and memory limits.",
                observed={
                    "cpu_limit": resource.attribute("cpu_limit", ""),
                    "memory_limit": resource.attribute("memory_limit", ""),
                },
                expected={"cpu_limit": "set", "memory_limit": "set"},
            ),
        )


class UnpinnedImage(ResourceRule):
    rule_id = "DA-SUPPLY-001"
    title = "Container images are pinned by digest"
    description = "A mutable tag means the artifact that passed review is not necessarily the artifact that runs."
    category = "supply_chain"
    severity = 3
    blocking = False
    automation_class = "patch"
    resource_types = (ResourceType.CONTAINER,)
    remediation = "Replace the tag with an immutable image digest (image@sha256:...)."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "CM-2"),
        ("NIST SP 800-53", "Rev. 5", "SI-7"),
        ("CIS Controls", "v8.1", "2.1"),
        ("ISO/IEC 27002", "2022", "A.8.28"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        image = str(resource.attribute("image", ""))
        if not image:
            return (RuleResult(MANUAL_REVIEW, "IMAGE_UNKNOWN", "No image reference is declared.", confidence=1),)
        if resource.attribute("image_digest_pinned"):
            return (RuleResult(PASS, "IMAGE_PINNED", "The image is pinned by digest."),)
        outcome = FAIL if context.target.is_production else WARNING
        return (
            RuleResult(
                outcome,
                "IMAGE_NOT_PINNED",
                f"Image {image!r} is referenced by a mutable tag.",
                observed={"image": image},
                expected={"image_digest_pinned": True},
                severity=None if outcome == FAIL else 2,
            ),
        )


class ImmutableRootFilesystem(ResourceRule):
    rule_id = "DA-K8S-005"
    title = "Containers use a read-only root filesystem"
    description = "A writable root filesystem lets an attacker persist tooling inside a running container."
    category = "configuration"
    severity = 2
    blocking = False
    automation_class = "patch"
    resource_types = (ResourceType.CONTAINER,)
    remediation = "Set readOnlyRootFilesystem and mount a writable emptyDir or tmpfs for scratch paths."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "CM-7"),
        ("NIST SP 800-53", "Rev. 5", "SI-7"),
        ("CIS Controls", "v8.1", "4.1"),
        ("ISO/IEC 27002", "2022", "A.8.9"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if resource.attribute("read_only_root_filesystem"):
            return (RuleResult(PASS, "ROOT_FILESYSTEM_READ_ONLY", "The root filesystem is read-only."),)
        return (
            RuleResult(
                WARNING,
                "ROOT_FILESYSTEM_WRITABLE",
                "The container root filesystem is writable.",
                expected={"read_only_root_filesystem": True},
            ),
        )


class PrivilegeEscalationAllowed(ResourceRule):
    rule_id = "DA-K8S-006"
    title = "Containers disallow privilege escalation"
    description = "allowPrivilegeEscalation permits a process to gain more privileges than its parent."
    category = "configuration"
    severity = 3
    blocking = False
    automation_class = "patch"
    resource_types = (ResourceType.CONTAINER,)
    remediation = "Set allowPrivilegeEscalation to false, or add no-new-privileges for Compose services."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "AC-6"),
        ("CIS Controls", "v8.1", "4.1"),
        ("ISO/IEC 27002", "2022", "A.8.2"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if not resource.attribute("allow_privilege_escalation", True):
            return (RuleResult(PASS, "NO_NEW_PRIVILEGES", "Privilege escalation is disabled."),)
        outcome = FAIL if context.target.is_production else WARNING
        return (
            RuleResult(
                outcome,
                "PRIVILEGE_ESCALATION_ALLOWED",
                "The container does not disable privilege escalation.",
                expected={"allow_privilege_escalation": False},
                severity=None if outcome == FAIL else 2,
            ),
        )


class BackupRetention(ResourceRule):
    rule_id = "DA-BACKUP-001"
    title = "Critical data has a backup plan meeting the retention baseline"
    description = "A database without a retained, restorable backup cannot survive corruption or ransomware."
    category = "backup"
    severity = 4
    blocking = False
    automation_class = "approval_required"
    resource_types = (ResourceType.DATABASE_INSTANCE, ResourceType.BACKUP_PLAN)
    remediation = "Attach a backup plan and set retention to at least the configured minimum."
    default_parameters = {"minimum_retention_days": 30}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "CP-9"),
        ("NIST SP 800-53", "Rev. 5", "CP-10"),
        ("CIS Controls", "v8.1", "11.2"),
        ("CIS Controls", "v8.1", "11.3"),
        ("ISO/IEC 27002", "2022", "A.8.13"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        minimum = int(context.parameter("minimum_retention_days", 30))
        retention = int(resource.attribute("backup_retention_days", resource.attribute("retention_days", 0)) or 0)
        if retention == 0:
            outcome = FAIL if (context.target.is_production and context.target.criticality >= 4) else WARNING
            return (
                RuleResult(
                    outcome,
                    "BACKUP_NOT_CONFIGURED",
                    "No backup retention is configured for this resource.",
                    observed={"retention_days": 0},
                    expected={"retention_days": minimum},
                    severity=None if outcome == FAIL else 3,
                ),
            )
        if retention < minimum:
            return (
                RuleResult(
                    WARNING,
                    "BACKUP_RETENTION_BELOW_MINIMUM",
                    f"Backup retention is {retention} days, below the required {minimum}.",
                    observed={"retention_days": retention},
                    expected={"retention_days": minimum},
                ),
            )
        return (RuleResult(PASS, "BACKUP_RETENTION_MET", f"Backup retention of {retention} days meets the baseline."),)


class InsecureTransportProtocol(ResourceRule):
    rule_id = "DA-TLS-001"
    title = "Endpoints require a modern TLS version"
    description = "TLS below 1.2 has known weaknesses and is refused by current compliance baselines."
    category = "encryption"
    severity = 4
    blocking = True
    automation_class = "patch"
    resource_types = (ResourceType.TLS_ENDPOINT, ResourceType.STORAGE_BUCKET)
    remediation = "Raise the minimum TLS version to 1.2 or higher and disable legacy cipher suites."
    default_parameters = {"minimum_tls_version": "1.2"}
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "SC-8"),
        ("NIST SP 800-53", "Rev. 5", "SC-13"),
        ("CIS Controls", "v8.1", "3.10"),
        ("ISO/IEC 27002", "2022", "A.8.24"),
        ("PCI DSS", "v4.0.1", "4"),
    )

    @staticmethod
    def _numeric(value: str) -> float:
        digits = "".join(character for character in str(value) if character.isdigit() or character == ".")
        try:
            return float(digits)
        except ValueError:
            return 0.0

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        declared = resource.attribute("min_tls_version") or resource.attribute("minimum_tls_version")
        if not declared:
            return (RuleResult(NOT_APPLICABLE, "TLS_VERSION_NOT_DECLARED", "No TLS minimum is declared here."),)
        minimum = context.parameter("minimum_tls_version", "1.2")
        if self._numeric(declared) >= self._numeric(minimum):
            return (RuleResult(PASS, "TLS_VERSION_ACCEPTABLE", f"Minimum TLS version is {declared}."),)
        return (
            RuleResult(
                FAIL,
                "INSECURE_TLS_VERSION",
                f"Minimum TLS version is {declared}, below the required {minimum}.",
                observed={"min_tls_version": str(declared)},
                expected={"min_tls_version": str(minimum)},
            ),
        )


class InstanceMetadataProtection(ResourceRule):
    rule_id = "DA-CONFIG-001"
    title = "Compute instances enforce hardened metadata access"
    description = (
        "Unauthenticated instance metadata (IMDSv1) turns a server-side request forgery bug "
        "into cloud credential theft."
    )
    category = "configuration"
    severity = 4
    blocking = False
    automation_class = "patch"
    resource_types = (ResourceType.COMPUTE_INSTANCE,)
    remediation = "Require session-oriented instance metadata (IMDSv2) and disable the legacy endpoint."
    mappings = (
        ("NIST SP 800-53", "Rev. 5", "CM-6"),
        ("NIST SP 800-53", "Rev. 5", "CM-7"),
        ("NIST SP 800-53", "Rev. 5", "IA-2"),
        ("CIS Controls", "v8.1", "4.1"),
        ("ISO/IEC 27002", "2022", "A.8.9"),
        ("PCI DSS", "v4.0.1", "2"),
    )

    def check(self, context: RuleContext, resource: Resource) -> Sequence[RuleResult]:
        if resource.attribute("imds_v2_required"):
            return (RuleResult(PASS, "IMDSV2_REQUIRED", "Hardened instance metadata is required."),)
        outcome = FAIL if (context.target.is_production or context.target.internet_exposed) else WARNING
        return (
            RuleResult(
                outcome,
                "IMDSV1_PERMITTED",
                "The instance permits unauthenticated metadata access.",
                observed={"imds_v2_required": False},
                expected={"imds_v2_required": True},
                severity=None if outcome == FAIL else 3,
            ),
        )


#: Declaration order is irrelevant — the engine sorts by ``rule_id``.
RULES: tuple[ResourceRule, ...] = (
    PublicAdminPort(),
    PublicDatabasePort(),
    EncryptionAtRest(),
    PublicObjectStorage(),
    PlaintextSecret(),
    CriticalVulnerability(),
    UnsupportedOperatingSystem(),
    AuditLoggingEnabled(),
    CentralizedLogDestination(),
    WildcardIdentityGrant(),
    PrivilegedContainer(),
    HostNamespaceAccess(),
    ContainerRunsAsRoot(),
    ContainerResourceLimits(),
    UnpinnedImage(),
    ImmutableRootFilesystem(),
    PrivilegeEscalationAllowed(),
    BackupRetention(),
    InsecureTransportProtocol(),
    InstanceMetadataProtection(),
)
