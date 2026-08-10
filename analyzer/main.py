import ast
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

try:
    from archive import inspect_archive
except ImportError:  # Local regression tests import the application copy.
    from core.archive import inspect_archive

PACK = "python-stdlib"
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
    return {
        "rule_id": rule_id,
        "rule_version": VERSION,
        **rule,
        "status": "needs_validation",
        "fingerprint": fingerprint,
        "file_path": path,
        "start_line": node.lineno,
        "end_line": getattr(node, "end_lineno", node.lineno),
        "snippet_hash": hashlib.sha256(line).hexdigest(),
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


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "normalize":
        from deployment_assurance.normalizers.cli import main as normalize

        raise SystemExit(normalize(["normalizer", *sys.argv[2:]]))
    archive_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    findings = []
    analyzed = unsupported = parse_failures = 0
    with tempfile.TemporaryDirectory(prefix="repository-") as directory:
        repository = Path(directory)
        extract(archive_path, repository)
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
    output = {
        "pack": PACK,
        "pack_version": VERSION,
        "coverage": {
            "status": "experimental",
            "analyzed_python_files": analyzed,
            "unsupported_files": unsupported,
            "parse_failures": parse_failures,
        },
        "findings": findings,
    }
    output_path.write_text(json.dumps(output, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
