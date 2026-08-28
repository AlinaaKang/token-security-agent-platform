from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agent.fusion import FusionReason
from app.knowledge.models import KnowledgeId
from app.lab.models import LabToolId, assert_public_payload, safer_action
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

    @field_validator("created_at", mode="after", check_fields=False)
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("persisted created_at must be timezone-aware")
        return value.astimezone(UTC)

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
    source_action: Decision
    effective_action: Decision
    receipt_id: NonEmptyText | None = None
    artifact_id: NonEmptyText | None = None
    error_code: LabExecutionErrorCode | None = None
    evidence_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    latency_ms: float = Field(ge=0)
    created_at: datetime

    @model_validator(mode="after")
    def effective_action_cannot_weaken_source(self) -> LabToolExecution:
        if self.effective_action != safer_action(
            self.source_action, self.effective_action
        ):
            raise ValueError("effective_action cannot be weaker than source_action")
        return self


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

    @model_validator(mode="after")
    def payload_must_be_canonical_public_json(self) -> LabArtifact:
        validate_artifact_payload(self.media_type, self.payload)
        return self


def validate_artifact_payload(media_type: str, payload: bytes) -> None:
    if media_type != "application/json":
        raise ValueError("lab artifact media type is unsupported")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("lab artifact payload must be UTF-8 JSON") from error
    try:
        parsed = json.loads(decoded, parse_constant=_reject_nonstandard_json)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError("lab artifact payload must be JSON") from error
    if not isinstance(parsed, dict):
        raise ValueError("lab artifact payload root must be an object")
    assert_public_payload(parsed)
    canonical = json.dumps(
        parsed, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if payload != canonical:
        raise ValueError("lab artifact payload must use canonical JSON")


def normalize_persisted_created_at(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("persisted created_at must be timezone-aware")
    return value.astimezone(UTC)


def _reject_nonstandard_json(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")
