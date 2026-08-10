"""The standalone CI client must fail closed for every terminal path."""

import importlib.util
import io
import urllib.error
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest


def _gate():
    path = Path(__file__).parents[3] / "bin" / "trishul-gate"
    loader = SourceFileLoader("trishul_gate", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("decision", "exit_code"),
    [
        ("approved", 0),
        ("approved_with_actions", 0),
        ("blocked", 1),
        ("manual_review", 2),
        ("error", 4),
    ],
)
def test_main_maps_every_decision_to_a_fail_closed_exit(monkeypatch, tmp_path, decision, exit_code):
    gate = _gate()
    artifact = tmp_path / "plan.json"
    artifact.write_text("{}")
    monkeypatch.setenv("TRISHUL_TOKEN", "test")
    monkeypatch.setattr(gate, "submit", lambda *_: {"id": "snapshot"})
    monkeypatch.setattr(gate, "evaluate", lambda *_: {"evaluation_run_id": "run"})
    monkeypatch.setattr(
        gate,
        "await_decision",
        lambda *_args, **_kwargs: {
            "decision": decision,
            "risk_score": "0.00",
            "compliance_score": "100.00",
            "reason_codes": [],
            "counts": {},
            "decision_hash": "a" * 64,
            "integrity_verified": True,
        },
    )
    monkeypatch.setattr(gate, "report", lambda *_args, **_kwargs: None)

    arguments = ["--base-url", "https://trishul.test", "--target-id", "target", "--artifact", str(artifact)]
    assert gate.main(arguments) == exit_code
    if decision == "approved_with_actions":
        assert gate.main([*arguments, "--actions-require-review"]) == gate.EXIT_REVIEW


@pytest.mark.parametrize("state", ["failed", "cancelled"])
def test_non_completed_terminal_runs_are_operational_failures(monkeypatch, state):
    gate = _gate()
    monkeypatch.setattr(gate, "_request", lambda *_args, **_kwargs: {"state": state, "error_code": "WORKER_FAILED"})

    with pytest.raises(gate.GateError, match=state):
        gate.await_decision("https://trishul.test", "token", "run", timeout=1, interval=0)


def test_timeout_and_warn_only_fail_closed(monkeypatch, tmp_path):
    gate = _gate()
    with pytest.raises(gate.GateTimeout, match="Timed out"):
        gate.await_decision("https://trishul.test", "token", "run", timeout=0, interval=0)

    artifact = tmp_path / "plan.json"
    artifact.write_text("{}")
    monkeypatch.setenv("TRISHUL_TOKEN", "test")
    monkeypatch.setattr(gate, "submit", lambda *_: (_ for _ in ()).throw(gate.GateError("offline")))
    common = ["--base-url", "https://trishul.test", "--target-id", "target", "--artifact", str(artifact)]
    assert gate.main(common) == gate.EXIT_ERROR
    assert gate.main([*common, "--warn-only"]) == gate.EXIT_OK

    monkeypatch.setattr(gate, "submit", lambda *_: {"id": "snapshot"})
    monkeypatch.setattr(gate, "evaluate", lambda *_: {"evaluation_run_id": "run"})
    monkeypatch.setattr(
        gate,
        "await_decision",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(gate.GateTimeout("slow")),
    )
    assert gate.main(common) == gate.EXIT_TIMEOUT


@pytest.mark.parametrize(
    "decision",
    [
        {},
        {"decision": "unknown", "decision_hash": "a" * 64, "integrity_verified": True},
        {"decision": "approved", "decision_hash": "bad", "integrity_verified": True},
        {"decision": "approved", "decision_hash": "a" * 64, "integrity_verified": False},
    ],
)
def test_malformed_and_integrity_mismatched_decisions_fail_closed(decision):
    gate = _gate()
    with pytest.raises(gate.GateError):
        gate.validate_decision(decision)


def test_authentication_and_malformed_json_fail_closed(monkeypatch):
    gate = _gate()
    unauthorized = urllib.error.HTTPError(
        "https://trishul.test", 401, "Unauthorized", {}, io.BytesIO(b'{"detail":"denied"}')
    )
    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(unauthorized))
    with pytest.raises(gate.GateError, match="HTTP 401"):
        gate._request("https://trishul.test", "token")

    class MalformedResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"not-json"

    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda *_args, **_kwargs: MalformedResponse())
    with pytest.raises(gate.GateError, match="Malformed JSON"):
        gate._request("https://trishul.test", "token")


def test_report_omits_resource_paths_and_private_rationale(monkeypatch, capsys):
    gate = _gate()
    decision = {
        "decision": "blocked",
        "risk_score": "90.00",
        "compliance_score": "50.00",
        "reason_codes": ["MANDATORY_CONTROL_FAILED"],
        "counts": {"fail": 1},
    }
    monkeypatch.setattr(
        gate,
        "_request",
        lambda *_args, **_kwargs: {
            "results": [
                {
                    "reason_code": "PUBLIC_ADMIN_PORT",
                    "resource_type": "network.ingress_rule",
                    "resource_id": "/private/customer/path",
                    "rationale": "private evidence text",
                    "fingerprint": "safe-result-id",
                }
            ]
        },
    )
    gate.report(decision, base="https://trishul.test", token="token", run_id="run")
    output = capsys.readouterr().out
    assert "safe-result-id" in output
    assert "/private/customer/path" not in output
    assert "private evidence text" not in output
