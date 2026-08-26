from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator

from app.agent.fusion import FusionReason
from app.semantic.models import SemanticCategory, SemanticSeverity
from app.knowledge.models import (
    KnowledgeEvidence,
    KnowledgeMode,
    KnowledgeStatus,
    ReportStatus,
)
from app.knowledge.reporting import GroundedReport


MAX_PROMPT_CHARACTERS = 32_768

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
DetectorStatus = Literal["no_token_anomaly", "token_anomaly_candidate"]
SemanticVerification = Literal["performed", "unavailable"]


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"
    SANITIZE_RECHECK = "sanitize_recheck"


class AnalysisRequest(BaseModel):
    prompt: str = Field(max_length=MAX_PROMPT_CHARACTERS)
    model_id: NonEmptyText
    mode: Literal["analysis", "gateway"] = "analysis"
    knowledge_mode: KnowledgeMode = KnowledgeMode.OFF

    @field_validator("prompt")
    @classmethod
    def prompt_must_contain_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("prompt must contain non-whitespace text")
        return value


class SuspiciousSpan(BaseModel):
    token_start: int = Field(ge=0)
    token_end: int = Field(ge=0)
    char_start: int = Field(ge=0)
    char_end: int = Field(ge=0)


class TokenSignal(BaseModel):
    index: int = Field(ge=0)
    token_id: int = Field(ge=0)
    token_text: str
    entropy: float = Field(ge=0)
    nll: float = Field(ge=0)
    cpd_entropy: float = Field(ge=0)
    cpd_nll: float = Field(ge=0)
    risk: float = Field(ge=0, le=1)


class Evidence(BaseModel):
    source: NonEmptyText
    summary: NonEmptyText


class Provenance(BaseModel):
    model_id: NonEmptyText
    tokenizer_id: NonEmptyText
    system_prompt_hash: NonEmptyText
    calibration_version: NonEmptyText
    thresholds: dict[str, float] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    request_id: NonEmptyText
    decision: Decision
    risk_score: float = Field(ge=0, le=1)
    detector_score: float = Field(ge=0)
    detector_status: DetectorStatus
    semantic_severity: SemanticSeverity
    semantic_categories: list[SemanticCategory]
    semantic_model_id: NonEmptyText
    semantic_model_version: NonEmptyText
    semantic_latency_ms: float = Field(ge=0)
    semantic_verification: SemanticVerification
    fusion_reason: FusionReason
    audit_persisted: bool = False
    suspicious_span: SuspiciousSpan | None = None
    signals: list[TokenSignal]
    evidence: list[Evidence]
    actions: list[NonEmptyText]
    provenance: Provenance
    latency_ms: float = Field(ge=0)
    knowledge_status: KnowledgeStatus = KnowledgeStatus.OFF
    knowledge_snapshot_version: NonEmptyText | None = None
    knowledge_latency_ms: float = Field(default=0.0, ge=0)
    knowledge_retrieval_latency_ms: float = Field(default=0.0, ge=0)
    knowledge_report_latency_ms: float = Field(default=0.0, ge=0)
    knowledge_evidence: list[KnowledgeEvidence] = Field(default_factory=list)
    grounded_report: GroundedReport | None = None
    report_status: ReportStatus = ReportStatus.OFF
