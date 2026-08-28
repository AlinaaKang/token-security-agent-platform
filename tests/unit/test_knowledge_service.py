from __future__ import annotations

from pathlib import Path

from app.knowledge.loader import load_knowledge_snapshot
from app.knowledge.query import SafeQueryBuilder
from app.knowledge.reporting import (
    DeterministicReportComposer,
    ReportGeneration,
)
from app.knowledge.retriever import LocalKnowledgeRetriever
from app.knowledge.service import KnowledgeService
from app.schemas import AnalysisResult


def _result() -> AnalysisResult:
    return AnalysisResult.model_validate(
        {
            "request_id": "req-knowledge",
            "decision": "block",
            "risk_score": 1.0,
            "detector_score": 5.0,
            "detector_status": "token_anomaly_candidate",
            "semantic_severity": "unsafe",
            "semantic_categories": ["jailbreak"],
            "semantic_model_id": "guard-model",
            "semantic_model_version": "guard-v1",
            "semantic_latency_ms": 4.0,
            "semantic_verification": "performed",
            "fusion_reason": "semantic_unsafe",
            "suspicious_span": {
                "token_start": 2,
                "token_end": 4,
                "char_start": 10,
                "char_end": 24,
            },
            "signals": [],
            "evidence": [],
            "actions": ["block"],
            "provenance": {
                "model_id": "qwen-model",
                "tokenizer_id": "qwen-tokenizer",
                "system_prompt_hash": "sha256:system",
                "calibration_version": "cal-v1",
            },
            "latency_ms": 12.5,
        }
    )


class TrapComponent:
    def __getattr__(self, name: str):
        raise AssertionError(f"off mode accessed {name}")


class DeterministicGenerator:
    def generate(self, facts, evidence) -> ReportGeneration:
        return ReportGeneration(
            report=DeterministicReportComposer().compose(facts, evidence),
            status="fallback",
            failure_code="runtime_error",
        )


class FailingRetriever:
    def search(self, query, *, top_k: int):
        raise RuntimeError("SAFE_PRIVATE_QUERY")


def _service(*, generator=None, retriever=None) -> KnowledgeService:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v1"))
    return KnowledgeService(
        snapshot_version=snapshot.manifest.snapshot_version,
        query_builder=SafeQueryBuilder(),
        retriever=retriever or LocalKnowledgeRetriever(snapshot),
        generator=generator,
        max_results=3,
    )


def test_off_mode_never_accesses_knowledge_components() -> None:
    service = KnowledgeService(
        snapshot_version="official-v1",
        query_builder=TrapComponent(),
        retriever=TrapComponent(),
        generator=TrapComponent(),
    )

    enhancement = service.enhance(
        prompt="SAFE_PRIVATE_QUERY",
        result=_result(),
        mode="off",
    )

    assert enhancement.knowledge_status == "off"
    assert enhancement.knowledge_evidence == ()
    assert enhancement.report_status == "off"


def test_evidence_mode_retrieves_without_generation() -> None:
    enhancement = _service(generator=TrapComponent()).enhance(
        prompt="请分析提示词注入风险。PRIVATE_SUFFIX",
        result=_result(),
        mode="evidence",
        attack_family="AutoDAN",
    )

    assert enhancement.knowledge_status == "ready"
    assert enhancement.knowledge_snapshot_version == "official-v1"
    assert enhancement.knowledge_evidence
    assert enhancement.grounded_report is None
    assert enhancement.report_status == "off"


def test_report_mode_returns_explicit_fallback_status() -> None:
    result = _result()
    enhancement = _service(generator=DeterministicGenerator()).enhance(
        prompt="请分析提示词注入风险。PRIVATE_SUFFIX",
        result=result,
        mode="report",
        attack_family="AutoDAN",
    )

    assert enhancement.knowledge_status == "degraded"
    assert enhancement.grounded_report is not None
    assert enhancement.report_status == "fallback"
    assert enhancement.grounded_report.evidence_ids == tuple(
        item.knowledge_id for item in enhancement.knowledge_evidence
    )
    assert result.decision == "block"
    assert result.actions == ["block"]


def test_retrieval_failure_returns_unavailable_without_private_details() -> None:
    enhancement = _service(retriever=FailingRetriever()).enhance(
        prompt="SAFE_PRIVATE_QUERY",
        result=_result(),
        mode="report",
    )

    serialized = enhancement.model_dump_json()
    assert enhancement.knowledge_status == "unavailable"
    assert enhancement.report_status == "unavailable"
    assert "SAFE_PRIVATE_QUERY" not in serialized
