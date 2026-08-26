from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.agent.fusion import FusionReason
from app.schemas import Decision, DetectorStatus, NonEmptyText
from app.semantic.models import SemanticCategory, SemanticSeverity
from app.knowledge.models import (
    KnowledgeId,
    KnowledgeMode,
    KnowledgeStatus,
    ReportStatus,
)


class SecurityEvent(BaseModel, frozen=True):
    request_id: NonEmptyText
    created_at: datetime
    prompt_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    prompt_char_count: int = Field(ge=1)
    token_count: int = Field(ge=0)
    detector_score: float = Field(ge=0)
    k: float = Field(ge=0)
    h: float = Field(gt=0)
    onset_token: int | None = Field(default=None, ge=0)
    detector_status: DetectorStatus
    decision: Decision
    mode: Literal["analysis", "gateway"]
    model_id: NonEmptyText
    calibration_version: NonEmptyText
    latency_ms: float = Field(ge=0)
    semantic_severity: SemanticSeverity | None = None
    semantic_categories: list[SemanticCategory] | None = None
    semantic_model_id: NonEmptyText | None = None
    semantic_model_version: NonEmptyText | None = None
    semantic_latency_ms: float | None = Field(default=None, ge=0)
    fusion_reason: FusionReason | None = None
    knowledge_snapshot_version: NonEmptyText | None = None
    knowledge_mode: KnowledgeMode | None = None
    knowledge_status: KnowledgeStatus | None = None
    knowledge_card_ids: list[KnowledgeId] | None = Field(
        default=None,
        max_length=3,
    )
    report_status: ReportStatus | None = None
    knowledge_latency_ms: float | None = Field(default=None, ge=0)

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value


class EventPage(BaseModel, frozen=True):
    items: list[SecurityEvent]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
