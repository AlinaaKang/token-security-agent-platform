from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent.fusion import FusionReason
from app.knowledge.models import KnowledgeId
from app.lab.models import LabToolId, assert_public_payload
from app.schemas import Decision, DetectorStatus, NonEmptyText
from app.semantic.models import SemanticCategory, SemanticSeverity


class LabExecutionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class LabExecutionErrorCode(StrEnum):
    EXECUTION_FAILED = "execution_failed"
    ARTIFACT_WRITE_FAILED = "artifact_write_failed"
    SIMULATED_TOOL_FAILURE = "simulated_tool_failure"


class LabCaseHandlingStatus(StrEnum):
    OPEN = "open"
    CONTAINED = "contained"
    CLOSED = "closed"


class _FrozenPublicRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def reject_non_public_fields(self) -> _FrozenPublicRecord:
        assert_public_payload(self.model_dump(mode="json"))
        return self


class LabExecuteRequest(_FrozenPublicRecord):
    confirmed: Literal[True]
    idempotency_key: UUID


class LabToolExecution(_FrozenPublicRecord):
    execution_id: NonEmptyText
    run_id: NonEmptyText
    tool_id: LabToolId
    idempotency_key: UUID
    status: LabExecutionStatus
    effective_action: Decision
    receipt_id: NonEmptyText | None = None
    artifact_id: NonEmptyText | None = None
    error_code: LabExecutionErrorCode | None = None
    evidence_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    latency_ms: float = Field(ge=0)
    created_at: datetime


class LabSecurityCase(_FrozenPublicRecord):
    case_id: NonEmptyText
    run_id: NonEmptyText
    created_at: datetime
    risk_score: float = Field(ge=0, le=1)
    semantic_severity: SemanticSeverity
    semantic_categories: tuple[SemanticCategory, ...] = ()
    detector_status: DetectorStatus
    anomaly_char_start: int | None = Field(default=None, ge=0)
    fusion_reason: FusionReason
    effective_action: Decision
    handling_status: LabCaseHandlingStatus
    knowledge_ids: tuple[KnowledgeId, ...] = ()
    model_id: NonEmptyText
    calibration_version: NonEmptyText
    knowledge_snapshot_version: NonEmptyText | None = None
    execution_id: NonEmptyText
    receipt_id: NonEmptyText | None = None


class LabArtifact(_FrozenPublicRecord):
    artifact_id: NonEmptyText
    run_id: NonEmptyText
    execution_id: NonEmptyText
    media_type: NonEmptyText
    payload: bytes = Field(exclude=True, repr=False)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    created_at: datetime
