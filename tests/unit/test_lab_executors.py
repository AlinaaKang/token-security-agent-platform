from __future__ import annotations

import builtins
import hashlib
import inspect
import socket
import subprocess
from pathlib import Path
from uuid import UUID

import pytest

from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.executors import LabToolExecutor
from app.lab.models import LabRunResult, LabToolId


_KEY = UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff")


def _run(decision: str = "block") -> LabRunResult:
    severity = "unsafe" if decision == "block" else "safe"
    fusion_reason = "semantic_unsafe" if decision == "block" else "all_clear"
    return LabRunResult.model_validate(
        {
            "run_id": "run_executor",
            "scenario_id": "scenario_executor",
            "scenario_kind": "synthetic",
            "scenario_label": "Executor test scenario",
            "mode": "gateway",
            "created_at": "2026-08-28T08:00:00Z",
            "stages": [],
            "detection": {
                "decision": decision,
                "risk_score": 0.9,
                "detector_score": 9.0,
                "detector_status": "token_anomaly_candidate",
                "semantic_severity": severity,
                "semantic_categories": ["jailbreak"] if decision == "block" else [],
                "semantic_model_id": "guard-model-v1",
                "semantic_model_version": "display-version-must-not-persist",
                "semantic_latency_ms": 1.0,
                "fusion_reason": fusion_reason,
                "suspicious_span": {"token_start": 1, "token_end": 2, "char_start": 3, "char_end": 4},
                "signals": [],
                "provenance": {
                    "model_id": "detector-model-v1",
                    "tokenizer_id": "detector-tokenizer-v1",
                    "system_prompt_hash": "sha256:internal-system",
                    "calibration_version": "display-calibration-must-not-persist",
                    "thresholds": {"risk": 0.5},
                },
                "latency_ms": 2.0,
                "knowledge_status": "ready",
                "knowledge_snapshot_version": "display-snapshot-must-not-persist",
                "knowledge_latency_ms": 0.0,
                "knowledge_evidence": [
                    {
                        "knowledge_id": "owasp-llm01-prompt-injection",
                        "title_zh": "Prompt injection controls",
                        "risk_domain": "prompt_injection",
                        "summary": "Structured evidence only.",
                        "recommendations": ["Preserve the immutable action."],
                        "source": {
                            "publisher": "owasp",
                            "title": "OWASP GenAI Security Project",
                            "url": "https://genai.owasp.org/",
                            "version": "2025",
                            "verified_at": "2026-08-26T00:00:00Z",
                            "usage_note": "official summary",
                        },
                        "retrieval_score": 4.0,
                        "matched_tags": ["jailbreak"],
                    }
                ],
                "report_status": "fallback",
            },
            "counterfactual": {
                "interpretation": "unchanged",
                "reason": "no_predicted_onset",
                "calibration_version": "calibration-v1",
                "original": {
                    "semantic_severity": severity,
                    "detector_status": "token_anomaly_candidate",
                    "risk_score": 0.9,
                    "detector_score": 9.0,
                    "decision": decision,
                    "latency_ms": 2.0,
                },
            },
            "tool_plans": [],
            "case_report": {
                "report_status": "deterministic",
                "summary": "Redacted summary.",
                "handling_steps": ["Retain the decision."],
                "limitations": ["No external tool is called."],
            },
        }
    )


@pytest.mark.parametrize(
    ("decision", "receipt_kind"),
    [
        ("allow", "allow_authorized"),
        ("review", "review_queued"),
        ("sanitize_recheck", "sanitize_recheck_queued"),
        ("block", "block_enforced"),
    ],
)
def test_gateway_creates_a_platform_receipt_from_the_immutable_decision(
    tmp_path: Path, decision: str, receipt_kind: str
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    executor = LabToolExecutor(store)

    bundle = executor.execute(_run(decision), LabToolId.GATEWAY_ENFORCEMENT, _KEY)

    assert tuple(inspect.signature(executor.execute).parameters) == (
        "run",
        "tool_id",
        "idempotency_key",
    )
    assert bundle.execution.status == "succeeded"
    assert bundle.execution.source_action == decision
    assert bundle.execution.effective_action == decision
    assert bundle.execution.execution_id.startswith("exec_")
    assert bundle.execution.receipt_id is not None
    assert bundle.execution.receipt_id.startswith("receipt_")
    assert bundle.receipt_kind == receipt_kind
    assert bundle.security_case is None
    assert bundle.artifact is None
    assert store.get_by_idempotency("run_executor", LabToolId.GATEWAY_ENFORCEMENT, _KEY) == bundle.execution
    store.close()


def test_security_case_creates_one_redacted_case_bound_to_its_execution(
    tmp_path: Path,
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    bundle = LabToolExecutor(store).execute(_run(), LabToolId.SECURITY_CASE, _KEY)

    assert bundle.security_case is not None
    assert bundle.security_case.case_id.startswith("case_")
    assert bundle.security_case.execution_id == bundle.execution.execution_id
    assert bundle.security_case.receipt_id == bundle.execution.receipt_id
    assert bundle.security_case.model_id == bundle.execution.model_provenance_sha256
    assert bundle.security_case.calibration_version == bundle.execution.calibration_provenance_sha256
    assert "display-version-must-not-persist" not in bundle.security_case.model_dump_json()
    assert store._connection.execute("SELECT COUNT(*) FROM lab_security_cases").fetchone()[0] == 1
    store.close()


def test_evidence_bundle_is_canonical_and_contains_prior_platform_receipts(
    tmp_path: Path,
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    executor = LabToolExecutor(store)
    run = _run()
    gateway = executor.execute(run, LabToolId.GATEWAY_ENFORCEMENT, UUID(int=1))
    security_case = executor.execute(run, LabToolId.SECURITY_CASE, UUID(int=2))

    first = executor.canonical_evidence_bytes(run, (gateway.execution, security_case.execution))
    second = executor.canonical_evidence_bytes(run, (gateway.execution, security_case.execution))
    bundle = executor.execute(run, LabToolId.EVIDENCE_BUNDLE, UUID(int=3))

    assert first == second
    assert first.endswith(b"\n")
    assert bundle.artifact is not None
    assert bundle.artifact.artifact_id.startswith("artifact_")
    assert bundle.artifact.payload == first
    assert bundle.execution.evidence_sha256 == "sha256:" + hashlib.sha256(first).hexdigest()
    payload = bundle.artifact.payload.decode("ascii")
    assert gateway.execution.execution_id in payload
    assert gateway.execution.receipt_id in payload
    assert security_case.execution.receipt_id in payload
    assert "display-version-must-not-persist" not in payload
    store.close()


def test_persistence_failure_returns_a_fixed_non_forged_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")

    def fail(*args: object, **kwargs: object) -> object:
        raise RuntimeError("private database failure")

    monkeypatch.setattr(store, "commit_result", fail)
    bundle = LabToolExecutor(store).execute(_run("block"), LabToolId.EVIDENCE_BUNDLE, _KEY)

    assert bundle.execution.status == "failed"
    assert bundle.execution.error_code == "persistence_failed"
    assert bundle.execution.source_action == "block"
    assert bundle.execution.effective_action == "block"
    assert bundle.execution.receipt_id is None
    assert bundle.execution.artifact_id is None
    assert bundle.execution.evidence_sha256 is None
    assert bundle.security_case is None
    assert bundle.artifact is None
    assert store.list_executions("run_executor") == ()
    store.close()


def test_idempotency_lookup_failure_is_also_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")

    def fail(*args: object, **kwargs: object) -> object:
        raise RuntimeError("private database failure")

    monkeypatch.setattr(store, "get_by_idempotency", fail)
    bundle = LabToolExecutor(store).execute(_run("review"), LabToolId.GATEWAY_ENFORCEMENT, _KEY)

    assert bundle.execution.status == "failed"
    assert bundle.execution.error_code == "persistence_failed"
    assert bundle.execution.source_action == "review"
    assert bundle.execution.effective_action == "review"
    assert bundle.execution.receipt_id is None
    assert bundle.execution.artifact_id is None
    store.close()


def test_executor_performs_no_network_subprocess_or_filesystem_artifact_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external side effect attempted")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)

    result = LabToolExecutor(store).execute(_run(), LabToolId.GATEWAY_ENFORCEMENT, _KEY)

    assert result.execution.status == "succeeded"
    assert list(tmp_path.iterdir()) == [tmp_path / "lab.sqlite3"]
    store.close()
