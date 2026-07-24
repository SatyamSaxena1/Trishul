#!/usr/bin/env python3
import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def zap_bundle(source, commit, target):
    body = json.loads(Path(source).read_text(encoding="utf-8"))
    findings = []
    for site in body.get("site", []):
        for alert in site.get("alerts", []):
            rule_id = str(alert.get("pluginid", "zap"))
            for instance in alert.get("instances") or [{}]:
                url = instance.get("uri") or target
                method = instance.get("method", "GET")
                parameter = instance.get("param", "")
                fingerprint = hashlib.sha256(f"{rule_id}:{method}:{url}:{parameter}".encode()).hexdigest()
                findings.append(
                    {
                        "rule_id": f"ZAP-{rule_id}",
                        "rule_version": str(body.get("@version", "1.0")),
                        "title": alert.get("name", "OWASP ZAP finding"),
                        "description": alert.get("desc", ""),
                        "cwe": f"CWE-{alert['cweid']}" if str(alert.get("cweid", "0")) != "0" else "",
                        "severity": min(5, int(alert.get("riskcode", 0)) + 1),
                        "confidence": min(5, int(alert.get("confidence", 0)) + 1),
                        "fingerprint": fingerprint,
                        "remediation": alert.get("solution", ""),
                        "evidence": [
                            {
                                "evidence_type": "http",
                                "location": {
                                    "url": url,
                                    "method": method,
                                    "parameter": parameter,
                                    "response_evidence_hash": hashlib.sha256(
                                        str(instance.get("evidence", "")).encode()
                                    ).hexdigest(),
                                    "zap_rule": rule_id,
                                },
                            }
                        ],
                    }
                )
    return {
        "schema": "trishul-ci-results-v1",
        "commit_sha": commit,
        "pack": "zap",
        "pack_version": str(body.get("@version", "1.0")),
        "coverage": {
            "target": target.rstrip("/"),
            "authenticated": False,
            "advisory": True,
            "requests_per_second": 5,
            "duration_seconds": 0,
        },
        "findings": findings,
    }


def junit_bundle(source, commit):
    data = Path(source).read_bytes()
    if len(data) > 10 * 1024 * 1024 or b"<!DOCTYPE" in data.upper():
        raise ValueError("JUnit input is too large or contains a document type.")
    root = ET.fromstring(data)  # noqa: S314 - bounded input with DTD/entity declarations rejected.
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    totals = {
        name: sum(int(suite.attrib.get(name, 0)) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    }
    totals["duration_seconds"] = sum(float(suite.attrib.get("time", 0)) for suite in suites)
    totals["artifact_hash"] = hashlib.sha256(data).hexdigest()
    return {
        "schema": "trishul-ci-results-v1",
        "commit_sha": commit,
        "pack": "ci-tests",
        "pack_version": "1.0",
        "coverage": totals,
        "findings": [],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("zap", "junit"))
    parser.add_argument("source")
    parser.add_argument("output")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--target")
    args = parser.parse_args()
    if args.kind == "zap" and not args.target:
        parser.error("--target is required for ZAP results")
    bundle = zap_bundle(args.source, args.commit, args.target) if args.kind == "zap" else junit_bundle(
        args.source, args.commit
    )
    Path(args.output).write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    main()
