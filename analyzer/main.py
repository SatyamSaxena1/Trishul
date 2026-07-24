import ast
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

try:
    from archive import inspect_archive
except ImportError:  # Local regression tests import the application copy.
    from core.archive import inspect_archive

VERSION = "1.0"

RULES = {
    "PY001": {
        "title": "Shell command execution enabled",
        "description": "A subprocess call enables shell parsing. Confirm whether untrusted data can reach the command.",
        "cwe": "CWE-78",
        "asvs": "V5",
        "severity": 5,
        "confidence": 4,
        "remediation": "Pass an argument list with shell=False and validate every externally controlled argument.",
    },
    "PY002": {
        "title": "TLS certificate verification disabled",
        "description": "An outbound request explicitly disables certificate verification.",
        "cwe": "CWE-295",
        "asvs": "V9",
        "severity": 4,
        "confidence": 5,
        "remediation": (
            "Enable certificate and hostname verification and use an approved CA bundle for private services."
        ),
    },
    "PY003": {
        "title": "Unsafe YAML loader selected",
        "description": "YAML deserialization uses an unsafe loader that may construct arbitrary Python objects.",
        "cwe": "CWE-502",
        "asvs": "V5",
        "severity": 5,
        "confidence": 5,
        "remediation": "Use yaml.safe_load or SafeLoader and validate the resulting data against a strict schema.",
    },
}


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def finding(rule_id, path, node, source_lines):
    rule = RULES[rule_id]
    line = source_lines[node.lineno - 1].strip().encode()
    fingerprint = hashlib.sha256(f"{rule_id}:{path}:{node.lineno}:{node.col_offset}".encode()).hexdigest()
    evidence = {
        "evidence_type": "source",
        "location": {
            "file_path": path,
            "start_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "snippet_hash": hashlib.sha256(line).hexdigest(),
        },
    }
    return {
        "rule_id": rule_id,
        "rule_version": VERSION,
        **rule,
        "status": "needs_validation",
        "language": "python",
        "fingerprint": fingerprint,
        "evidence": [evidence],
    }


def scan_python(path, relative):
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative)
    except (UnicodeDecodeError, SyntaxError):
        return [], False
    lines = source.splitlines()
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node.func)
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        shell = keywords.get("shell")
        verify = keywords.get("verify")
        loader = keywords.get("Loader")
        if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "os.system"} and (
            name == "os.system" or isinstance(shell, ast.Constant) and shell.value is True
        ):
            results.append(finding("PY001", relative, node, lines))
        if (
            name.endswith(
                ("requests.get", "requests.post", "requests.put", "requests.delete", "httpx.get", "httpx.post")
            )
            and isinstance(verify, ast.Constant)
            and verify.value is False
        ):
            results.append(finding("PY002", relative, node, lines))
        if name.endswith("yaml.load") and loader and call_name(loader).endswith(("UnsafeLoader", "FullLoader")):
            results.append(finding("PY003", relative, node, lines))
    return results, True


def extract(archive_path, destination):
    with archive_path.open("rb") as stream:
        inspect_archive(stream)
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            for entry in archive.infolist():
                target = destination / entry.filename
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
    else:
        with tarfile.open(archive_path, "r:*") as archive:
            archive.extractall(destination, filter="data")


def _severity(value):
    return {"UNKNOWN": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}.get(str(value).upper(), 3)


def _source_evidence(repository, path, start=0, end=0):
    source = repository / path
    digest = ""
    if source.is_file() and start:
        try:
            line = source.read_text(encoding="utf-8").splitlines()[start - 1].strip().encode()
            digest = hashlib.sha256(line).hexdigest()
        except (IndexError, OSError, UnicodeDecodeError):
            pass
    return {
        "evidence_type": "source",
        "location": {
            "file_path": path,
            "start_line": start,
            "end_line": end or start,
            "snippet_hash": digest,
        },
    }


def scan_semgrep(repository):
    command = [
        "semgrep",
        "scan",
        "--config",
        "/app/rules.yml",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--max-target-bytes=10000000",
        str(repository),
    ]
    result = subprocess.run(  # noqa: S603 - fixed executable and non-executing scanner arguments.
        command, check=False, capture_output=True, text=True, timeout=1200
    )
    if result.returncode:
        raise RuntimeError("Semgrep failed.")
    body = json.loads(result.stdout)
    findings = []
    for item in body.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        raw_path = Path(item["path"])
        try:
            path = raw_path.relative_to(repository).as_posix()
        except ValueError:
            path = raw_path.as_posix()
        start = item.get("start", {}).get("line", 0)
        end = item.get("end", {}).get("line", start)
        rule_id = item["check_id"]
        cwe = metadata.get("cwe", "")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        findings.append(
            {
                "rule_id": rule_id,
                "rule_version": VERSION,
                "title": metadata.get("shortlink") or rule_id.replace("-", " ").title(),
                "description": extra.get("message", "Semgrep matched a reviewed security rule."),
                "cwe": str(cwe)[:30],
                "asvs": str(metadata.get("owasp", ""))[:60],
                "severity": _severity(extra.get("severity")),
                "confidence": _severity(metadata.get("confidence", "MEDIUM")),
                "status": "needs_validation",
                "language": (
                    metadata.get("technology", [""])[0]
                    if isinstance(metadata.get("technology"), list)
                    else str(metadata.get("technology", ""))
                ),
                "remediation": metadata.get("fix", "Review the data flow and replace the unsafe operation."),
                "fingerprint": hashlib.sha256(f"{rule_id}:{path}:{start}:{end}".encode()).hexdigest(),
                "evidence": [_source_evidence(repository, path, start, end)],
            }
        )
    return findings


def scan_trivy(repository):
    command = [
        "trivy",
        "filesystem",
        "--format",
        "json",
        "--scanners",
        "vuln,secret,misconfig",
        "--offline-scan",
        "--skip-db-update",
        "--skip-check-update",
        "--cache-dir",
        "/trivy-cache",
        str(repository),
    ]
    result = subprocess.run(  # noqa: S603 - fixed executable and non-executing scanner arguments.
        command, check=False, capture_output=True, text=True, timeout=1200
    )
    if result.returncode:
        raise RuntimeError("Trivy failed.")
    findings = []
    for scanned in json.loads(result.stdout).get("Results", []):
        target = scanned.get("Target", "")
        for item in scanned.get("Vulnerabilities") or []:
            rule_id = item.get("VulnerabilityID", "dependency-vulnerability")
            package = item.get("PkgName", "")
            installed = item.get("InstalledVersion", "")
            fixed = item.get("FixedVersion", "")
            findings.append(
                {
                    "rule_id": rule_id,
                    "rule_version": VERSION,
                    "title": item.get("Title") or f"Vulnerable dependency: {package}",
                    "description": (
                        item.get("Description") or f"{package} {installed} is affected by {rule_id}."
                    )[:8000],
                    "cwe": (item.get("CweIDs") or [""])[0],
                    "asvs": "",
                    "severity": _severity(item.get("Severity")),
                    "confidence": 5,
                    "status": "candidate",
                    "language": item.get("PkgIdentifier", {}).get("PURL", "").split(":", 1)[0],
                    "remediation": f"Upgrade {package} to {fixed}." if fixed else f"Review or replace {package}.",
                    "fingerprint": hashlib.sha256(
                        f"{rule_id}:{target}:{package}:{installed}".encode()
                    ).hexdigest(),
                    "evidence": [
                        {
                            "evidence_type": "dependency",
                            "location": {
                                "package": package,
                                "installed_version": installed,
                                "fixed_version": fixed,
                                "ecosystem": item.get("PkgIdentifier", {}).get("PURL", "").split(":", 1)[0],
                                "lockfile": target,
                            },
                        }
                    ],
                }
            )
        for item in scanned.get("Secrets") or []:
            start = item.get("StartLine", 0)
            rule_id = item.get("RuleID", "secret")
            findings.append(
                {
                    "rule_id": rule_id,
                    "rule_version": VERSION,
                    "title": item.get("Title", "Secret detected"),
                    "description": item.get("Category", "A possible secret is present in source."),
                    "cwe": "CWE-798",
                    "asvs": "V6",
                    "severity": _severity(item.get("Severity", "HIGH")),
                    "confidence": 4,
                    "status": "needs_validation",
                    "language": "",
                    "remediation": "Remove and rotate the secret, then use an approved secret store.",
                    "fingerprint": hashlib.sha256(f"{rule_id}:{target}:{start}".encode()).hexdigest(),
                    "evidence": [_source_evidence(repository, target, start, item.get("EndLine", start))],
                }
            )
        for item in scanned.get("Misconfigurations") or []:
            rule_id = item.get("ID", "misconfiguration")
            start = item.get("CauseMetadata", {}).get("StartLine", 0)
            findings.append(
                {
                    "rule_id": rule_id,
                    "rule_version": VERSION,
                    "title": item.get("Title", "Insecure configuration"),
                    "description": (item.get("Description") or "Trivy detected an insecure configuration.")[:8000],
                    "cwe": "",
                    "asvs": "",
                    "severity": _severity(item.get("Severity")),
                    "confidence": 4,
                    "status": "needs_validation",
                    "language": "",
                    "remediation": item.get("Resolution", "Harden the affected configuration."),
                    "fingerprint": hashlib.sha256(f"{rule_id}:{target}:{start}".encode()).hexdigest(),
                    "evidence": [
                        {
                            "evidence_type": "configuration",
                            "location": {
                                "file_path": target,
                                "resource_type": item.get("Type", ""),
                                "configuration_path": item.get("CauseMetadata", {}).get("Code", {}).get("Lines", []),
                                "start_line": start,
                            },
                        }
                    ],
                }
            )
    return findings


def coverage(repository, pack, *, analyzed=0, unsupported=0, parse_failures=0):
    manifests = [
        path.relative_to(repository).as_posix()
        for path in repository.rglob("*")
        if path.is_file()
        and path.name
        in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "pyproject.toml"}
    ]
    npm_projects = [path for path in manifests if path.endswith("package.json")]
    lockfiles = [path for path in manifests if Path(path).name != "package.json"]
    warnings = []
    if npm_projects and not any(
        Path(lock).parent == Path(project).parent for project in npm_projects for lock in lockfiles
    ):
        warnings.append("dependency versions unavailable: npm project has no lockfile")
    return {
        "status": "experimental",
        "pack": pack,
        "detected_projects": manifests,
        "warnings": warnings,
        "analyzed_python_files": analyzed,
        "unsupported_files": unsupported,
        "parse_failures": parse_failures,
    }


def main():
    archive_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    pack = sys.argv[3] if len(sys.argv) > 3 else "python-stdlib"
    if pack not in {"python-stdlib", "semgrep", "trivy"}:
        raise SystemExit(f"Unsupported scan pack: {pack}")
    findings = []
    analyzed = unsupported = parse_failures = 0
    with tempfile.TemporaryDirectory(prefix="repository-") as directory:
        repository = Path(directory)
        extract(archive_path, repository)
        if pack == "python-stdlib":
            for path in repository.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix != ".py":
                    unsupported += 1
                    continue
                relative = path.relative_to(repository).as_posix()
                result, parsed = scan_python(path, relative)
                findings.extend(result)
                analyzed += int(parsed)
                parse_failures += int(not parsed)
        elif pack == "semgrep":
            findings = scan_semgrep(repository)
        else:
            findings = scan_trivy(repository)
        scan_coverage = coverage(
            repository,
            pack,
            analyzed=analyzed,
            unsupported=unsupported,
            parse_failures=parse_failures,
        )
    output = {
        "pack": pack,
        "pack_version": VERSION,
        "coverage": scan_coverage,
        "findings": findings,
    }
    output_path.write_text(json.dumps(output, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
