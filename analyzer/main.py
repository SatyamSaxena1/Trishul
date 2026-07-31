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

RULE_CONFIG_PATH = Path(__file__).with_name("rules") / "v1.json"


def load_rule_config(path=RULE_CONFIG_PATH):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    if not config.get("configuration_version") or not config.get("pack_version"):
        raise ValueError("Rule configuration must be versioned")
    return config


RULE_CONFIG = load_rule_config()
PACK = RULE_CONFIG["pack"]
VERSION = RULE_CONFIG["pack_version"]
RULES = RULE_CONFIG["rules"]


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def finding(rule_id, path, node, source_lines):
    rule = {key: value for key, value in RULES[rule_id].items() if key not in {"enabled", "rule_version"}}
    line = source_lines[node.lineno - 1].strip().encode()
    fingerprint = hashlib.sha256(f"{rule_id}:{path}:{node.lineno}:{node.col_offset}".encode()).hexdigest()
    return {
        "rule_id": rule_id,
        "rule_version": RULES[rule_id]["rule_version"],
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
            if RULES["PY001"]["enabled"]:
                results.append(finding("PY001", relative, node, lines))
        if (
            name.endswith(
                ("requests.get", "requests.post", "requests.put", "requests.delete", "httpx.get", "httpx.post")
            )
            and isinstance(verify, ast.Constant)
            and verify.value is False
        ):
            if RULES["PY002"]["enabled"]:
                results.append(finding("PY002", relative, node, lines))
        if name.endswith("yaml.load") and loader and call_name(loader).endswith(("UnsafeLoader", "FullLoader")):
            if RULES["PY003"]["enabled"]:
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
        "rule_configuration_version": RULE_CONFIG["configuration_version"],
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
