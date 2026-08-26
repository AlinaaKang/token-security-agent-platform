from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.knowledge.models import (
    KnowledgeEvidence,
    KnowledgeMode,
    KnowledgeStatus,
    NormalizedSecurityFacts,
    ReportStatus,
)
from app.knowledge.query import RetrievalMetadata, SafeQueryBuilder
from app.knowledge.reporting import GroundedReport
from app.schemas import AnalysisResult


class KnowledgeEnhancement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    knowledge_status: KnowledgeStatus
    knowledge_snapshot_version: str | None
    knowledge_latency_ms: float = Field(ge=0)
    knowledge_retrieval_latency_ms: float = Field(ge=0)
    knowledge_report_latency_ms: float = Field(ge=0)
    knowledge_evidence: tuple[KnowledgeEvidence, ...]
    grounded_report: GroundedReport | None
    report_status: ReportStatus


def _off_enhancement() -> KnowledgeEnhancement:
    return KnowledgeEnhancement(
        knowledge_status=KnowledgeStatus.OFF,
        knowledge_snapshot_version=None,
        knowledge_latency_ms=0.0,
        knowledge_retrieval_latency_ms=0.0,
        knowledge_report_latency_ms=0.0,
        knowledge_evidence=(),
        grounded_report=None,
        report_status=ReportStatus.OFF,
    )


class KnowledgeService:
    def __init__(
        self,
        *,
        snapshot_version: str,
        query_builder: SafeQueryBuilder,
        retriever: Any,
        generator: Any | None,
        max_results: int = 3,
    ) -> None:
        if not snapshot_version.strip():
            raise ValueError("snapshot_version must not be blank")
        if not 1 <= max_results <= 3:
            raise ValueError("max_results must be between 1 and 3")
        self._snapshot_version = snapshot_version
        self._query_builder = query_builder
        self._retriever = retriever
        self._generator = generator
        self._max_results = max_results

    def enhance(
        self,
        *,
        prompt: str,
        result: AnalysisResult,
        mode: KnowledgeMode | str,
        attack_family: str | None = None,
        work_mode: str = "analysis",
    ) -> KnowledgeEnhancement:
        selected_mode = KnowledgeMode(mode)
        if selected_mode is KnowledgeMode.OFF:
            return _off_enhancement()

        started = time.perf_counter()
        retrieval_latency = 0.0
        try:
            retrieval_started = time.perf_counter()
            metadata = RetrievalMetadata(
                semantic_severity=result.semantic_severity,
                semantic_categories=tuple(result.semantic_categories),
                detector_status=result.detector_status,
                fusion_reason=result.fusion_reason,
                decision=result.decision,
                mode=work_mode,
                attack_family=attack_family,
            )
            query = self._query_builder.build(
                prompt,
                char_onset=(
                    result.suspicious_span.char_start
                    if result.suspicious_span is not None
                    else None
                ),
                metadata=metadata,
            )
            evidence = self._retriever.search(query, top_k=self._max_results)
            retrieval_latency = (time.perf_counter() - retrieval_started) * 1000
            if not evidence:
                return KnowledgeEnhancement(
                    knowledge_status=KnowledgeStatus.DEGRADED,
                    knowledge_snapshot_version=self._snapshot_version,
                    knowledge_latency_ms=(time.perf_counter() - started) * 1000,
                    knowledge_retrieval_latency_ms=retrieval_latency,
                    knowledge_report_latency_ms=0.0,
                    knowledge_evidence=(),
                    grounded_report=None,
                    report_status=(
                        ReportStatus.UNAVAILABLE
                        if selected_mode is KnowledgeMode.REPORT
                        else ReportStatus.OFF
                    ),
                )
            if selected_mode is KnowledgeMode.EVIDENCE:
                return KnowledgeEnhancement(
                    knowledge_status=KnowledgeStatus.READY,
                    knowledge_snapshot_version=self._snapshot_version,
                    knowledge_latency_ms=(time.perf_counter() - started) * 1000,
                    knowledge_retrieval_latency_ms=retrieval_latency,
                    knowledge_report_latency_ms=0.0,
                    knowledge_evidence=tuple(evidence),
                    grounded_report=None,
                    report_status=ReportStatus.OFF,
                )
            if self._generator is None:
                raise RuntimeError("knowledge report generator unavailable")
            report_started = time.perf_counter()
            facts = NormalizedSecurityFacts(
                semantic_severity=result.semantic_severity,
                semantic_categories=tuple(result.semantic_categories),
                detector_status=result.detector_status,
                anomaly_char_start=(
                    result.suspicious_span.char_start
                    if result.suspicious_span is not None
                    else None
                ),
                fusion_reason=result.fusion_reason,
                decision=result.decision.value,
                mode=metadata.mode,
                attack_family=attack_family,
            )
            generation = self._generator.generate(facts, evidence)
            report_latency = (time.perf_counter() - report_started) * 1000
            return KnowledgeEnhancement(
                knowledge_status=(
                    KnowledgeStatus.READY
                    if generation.status is ReportStatus.GENERATED
                    else KnowledgeStatus.DEGRADED
                ),
                knowledge_snapshot_version=self._snapshot_version,
                knowledge_latency_ms=(time.perf_counter() - started) * 1000,
                knowledge_retrieval_latency_ms=retrieval_latency,
                knowledge_report_latency_ms=report_latency,
                knowledge_evidence=tuple(evidence),
                grounded_report=generation.report,
                report_status=generation.status,
            )
        except Exception:
            return KnowledgeEnhancement(
                knowledge_status=KnowledgeStatus.UNAVAILABLE,
                knowledge_snapshot_version=self._snapshot_version,
                knowledge_latency_ms=(time.perf_counter() - started) * 1000,
                knowledge_retrieval_latency_ms=retrieval_latency,
                knowledge_report_latency_ms=0.0,
                knowledge_evidence=(),
                grounded_report=None,
                report_status=ReportStatus.UNAVAILABLE,
            )
