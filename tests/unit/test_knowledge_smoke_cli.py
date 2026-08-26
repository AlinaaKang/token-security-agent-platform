from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.smoke_knowledge_rag import run_smoke


class FakeClient:
    def __init__(self, *, mismatch: bool = False) -> None:
        self.calls: list[dict] = []
        self.mismatch = mismatch

    def get_json(self, url: str) -> dict:
        return {
            "model": {"ready": True, "model_id": "qwen-model"},
            "knowledge": {
                "ready": True,
                "snapshot_version": "official-v1",
                "card_count": 12,
                "generator_ready": True,
            },
        }

    def post_json(self, url: str, payload: dict) -> dict:
        self.calls.append(payload)
        report_mode = payload["knowledge_mode"] == "report"
        decision = "block" if self.mismatch and report_mode else "review"
        return {
            "decision": decision,
            "detector_score": 8.125,
            "detector_status": "token_anomaly_candidate",
            "suspicious_span": {
                "token_start": 4,
                "token_end": 6,
                "char_start": 12,
                "char_end": 24,
            },
            "semantic_severity": "safe",
            "semantic_categories": [],
            "semantic_verification": "performed",
            "fusion_reason": "cpd_candidate",
            "knowledge_status": "ready" if report_mode else "off",
            "knowledge_snapshot_version": "official-v1" if report_mode else None,
            "knowledge_evidence": ([{
                "knowledge_id": "owasp-llm01-prompt-injection",
                "summary": "SAFE_PRIVATE_CARD_SUMMARY",
                "source": {"title": "official"},
            }] if report_mode else []),
            "grounded_report": ({
                "summary": "SAFE_PRIVATE_REPORT_BODY",
                "evidence_ids": ["owasp-llm01-prompt-injection"],
                "handling_steps": ["SAFE_PRIVATE_RECOMMENDATION"],
                "limitations": ["fixed"],
            } if report_mode else None),
            "report_status": "fallback" if report_mode else "off",
            "latency_ms": 30.0,
            "knowledge_latency_ms": 3.0 if report_mode else 0.0,
            "knowledge_retrieval_latency_ms": 0.5 if report_mode else 0.0,
            "knowledge_report_latency_ms": 2.5 if report_mode else 0.0,
            "prompt": payload["prompt"],
            "query_text": "SAFE_PRIVATE_QUERY",
            "raw_output": "SAFE_PRIVATE_RAW_OUTPUT",
            "signals": [{"token_text": "SAFE_PRIVATE_TOKEN"}],
        }


def write_input(path: Path) -> None:
    rows = [
        {"sample_id": "protected-1", "prompt": "SAFE_PRIVATE_PROMPT_ONE", "mode": "analysis"},
        {"sample_id": "protected-2", "prompt": "SAFE_PRIVATE_PROMPT_TWO", "mode": "gateway"},
    ]
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in collect_keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in collect_keys(item)}
    return set()


def test_smoke_report_is_aggregate_only_and_compares_off_with_report() -> None:
    input_path = Path("tmp/test-knowledge-smoke-protected.jsonl")
    output_path = Path("tmp/test-knowledge-smoke-aggregate.json")
    input_path.parent.mkdir(exist_ok=True)
    write_input(input_path)
    client = FakeClient()

    try:
        report = run_smoke(
            input_path=input_path,
            api_base="http://127.0.0.1:18000",
            output_path=output_path,
            expected_snapshot_version="official-v1",
            client=client,
        )
        serialized = output_path.read_text(encoding="utf-8")
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)

    assert set(report) == {
        "schema_version",
        "expected_snapshot_version",
        "sample_count",
        "completed_pair_count",
        "mode_counts",
        "knowledge_status_counts",
        "card_id_counts",
        "report_status_counts",
        "citation_validity",
        "decision_invariance",
        "errors",
        "latency_ms",
    }
    assert report["sample_count"] == 2
    assert report["completed_pair_count"] == 2
    assert report["mode_counts"] == {"off": 2, "report": 2}
    assert report["knowledge_status_counts"] == {"off": 2, "ready": 2}
    assert report["card_id_counts"] == {"owasp-llm01-prompt-injection": 2}
    assert report["report_status_counts"] == {"fallback": 2, "off": 2}
    assert report["citation_validity"] == {"valid": 2, "total": 2, "rate": 1.0}
    assert report["decision_invariance"] == {"matched": 2, "total": 2, "rate": 1.0}
    assert report["errors"] == {}
    assert [call["knowledge_mode"] for call in client.calls] == ["off", "report", "off", "report"]
    assert "SAFE_PRIVATE" not in serialized
    report_keys = collect_keys(json.loads(serialized))
    for forbidden in ("prompt", "query_text", "raw_output", "token_text", "signals", "grounded_report"):
        assert forbidden not in report_keys


def test_smoke_records_invariance_failure_without_serializing_response() -> None:
    input_path = Path("tmp/test-knowledge-smoke-mismatch.jsonl")
    output_path = Path("tmp/test-knowledge-smoke-mismatch-output.json")
    input_path.parent.mkdir(exist_ok=True)
    write_input(input_path)

    try:
        report = run_smoke(
            input_path=input_path,
            api_base="http://127.0.0.1:18000",
            output_path=output_path,
            expected_snapshot_version="official-v1",
            client=FakeClient(mismatch=True),
        )
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)

    assert report["decision_invariance"] == {"matched": 0, "total": 2, "rate": 0.0}


def test_smoke_rejects_snapshot_mismatch_before_protected_requests() -> None:
    input_path = Path("tmp/test-knowledge-smoke-snapshot.jsonl")
    output_path = Path("tmp/test-knowledge-smoke-snapshot-output.json")
    input_path.parent.mkdir(exist_ok=True)
    write_input(input_path)
    client = FakeClient()

    try:
        with pytest.raises(RuntimeError, match="snapshot version mismatch"):
            run_smoke(
                input_path=input_path,
                api_base="http://127.0.0.1:18000",
                output_path=output_path,
                expected_snapshot_version="unexpected-v2",
                client=client,
            )
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)

    assert client.calls == []
