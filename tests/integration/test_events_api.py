from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.audit.store import SQLiteEventStore
from app.main import app
from app.schemas import AnalysisResult, Provenance


class StubWorkflow:
    def analyze(self, payload, *, request_id: str) -> AnalysisResult:
        return AnalysisResult(
            request_id=request_id,
            decision="block",
            risk_score=1.0,
            detector_score=5.0,
            detector_status="token_anomaly_candidate",
            semantic_severity="unsafe",
            semantic_categories=["violent"],
            semantic_model_id="guard-model",
            semantic_model_version="guard-v1",
            semantic_latency_ms=2.0,
            semantic_verification="performed",
            fusion_reason="semantic_unsafe",
            signals=[],
            evidence=[],
            actions=["block"],
            provenance=Provenance(
                model_id=payload.model_id,
                tokenizer_id=payload.model_id,
                system_prompt_hash="sha256:system",
                calibration_version="cal-v1",
                thresholds={"k": 0.0, "h": 1.7},
            ),
            latency_ms=12.5,
            knowledge_status="degraded",
            knowledge_snapshot_version="official-v1",
            knowledge_latency_ms=3.5,
            knowledge_retrieval_latency_ms=1.0,
            knowledge_report_latency_ms=2.5,
            knowledge_evidence=[
                {
                    "knowledge_id": "owasp-llm01-prompt-injection",
                    "title_zh": "提示词注入风险",
                    "risk_domain": "prompt_injection",
                    "summary": "knowledge card private summary",
                    "recommendations": ["private recommendation"],
                    "source": {
                        "publisher": "owasp",
                        "title": "LLM01: Prompt Injection",
                        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                        "version": "2025",
                        "verified_at": "2026-08-26T00:00:00Z",
                        "usage_note": "official summary",
                    },
                    "retrieval_score": 1.0,
                    "matched_tags": ["jailbreak"],
                }
            ],
            grounded_report={
                "summary": "grounded report private body",
                "evidence_ids": ["owasp-llm01-prompt-injection"],
                "handling_steps": ["private recommendation"],
                "limitations": ["knowledge does not change action"],
            },
            report_status="fallback",
        )


def test_analysis_persists_redacted_event_and_events_api_lists_it() -> None:
    database_path = Path("tmp/test-events-api.sqlite3")
    database_path.unlink(missing_ok=True)
    store = SQLiteEventStore(database_path)
    app.state.analysis_workflow = StubWorkflow()
    app.state.event_store = store
    try:
        analysis = TestClient(app).post(
            "/api/v1/analyze",
            json={
                "prompt": "SAFE_PRIVATE_PROMPT",
                "model_id": "qwen-model",
                "mode": "gateway",
            },
        )
        events = TestClient(app).get("/api/v1/events?limit=10&offset=0")
    finally:
        del app.state.analysis_workflow
        del app.state.event_store
        store.close()

    assert analysis.status_code == 200
    assert analysis.json()["audit_persisted"] is True
    assert events.status_code == 200
    payload = events.json()
    assert payload["total"] == 1
    assert payload["items"][0]["prompt_sha256"].startswith("sha256:")
    assert payload["items"][0]["semantic_severity"] == "unsafe"
    assert payload["items"][0]["semantic_categories"] == ["violent"]
    assert payload["items"][0]["fusion_reason"] == "semantic_unsafe"
    assert payload["items"][0]["knowledge_snapshot_version"] == "official-v1"
    assert payload["items"][0]["knowledge_card_ids"] == [
        "owasp-llm01-prompt-injection"
    ]
    assert payload["items"][0]["report_status"] == "fallback"
    assert "SAFE_PRIVATE_PROMPT" not in events.text
    database_bytes = database_path.read_bytes()
    assert b"SAFE_PRIVATE_PROMPT" not in database_bytes
    assert b"Safety: Unsafe" not in database_bytes
    assert b"knowledge card private summary" not in database_bytes
    assert b"grounded report private body" not in database_bytes
    assert b"private recommendation" not in database_bytes
    database_path.unlink(missing_ok=True)
