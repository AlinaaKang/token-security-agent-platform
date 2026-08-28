from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

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


PriorExecutionId = Annotated[
    str, StringConstraints(pattern=r"^exec_[0-9a-f]{32}$")
]
PriorReceiptId = Annotated[
    str, StringConstraints(pattern=r"^receipt_[0-9a-f]{32}$")
]
OpaqueProvenanceDigest = Annotated[
    str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")
]


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
    model_provenance_sha256: OpaqueProvenanceDigest
    calibration_provenance_sha256: OpaqueProvenanceDigest
    knowledge_snapshot_sha256: OpaqueProvenanceDigest | None = None
    knowledge_ids: tuple[KnowledgeId, ...] = ()
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
    model_id: OpaqueProvenanceDigest
    calibration_version: OpaqueProvenanceDigest
    knowledge_snapshot_version: OpaqueProvenanceDigest | None = None
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


class CanonicalEvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    artifact_kind: Literal["evidence_bundle"]
    detector_status: DetectorStatus
    risk_score: float = Field(ge=0, le=1)
    semantic_severity: SemanticSeverity
    semantic_categories: tuple[SemanticCategory, ...] = ()
    fusion_reason: FusionReason
    effective_action: Decision
    model_provenance_sha256: OpaqueProvenanceDigest
    calibration_provenance_sha256: OpaqueProvenanceDigest
    knowledge_snapshot_sha256: OpaqueProvenanceDigest | None = None
    knowledge_ids: tuple[KnowledgeId, ...] = ()
    prior_execution_ids: tuple[PriorExecutionId, ...] = ()
    prior_receipt_ids: tuple[PriorReceiptId, ...] = ()

    @model_validator(mode="after")
    def reject_non_public_fields(self) -> CanonicalEvidenceBundle:
        assert_public_payload(self.model_dump(mode="json"))
        return self


def validate_artifact_payload(media_type: str, payload: bytes) -> None:
    parse_canonical_evidence_bundle(media_type, payload)


def parse_canonical_evidence_bundle(
    media_type: str, payload: bytes
) -> CanonicalEvidenceBundle:
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
    try:
        bundle = CanonicalEvidenceBundle.model_validate(parsed)
    except ValueError as error:
        raise ValueError("lab artifact payload does not match evidence schema") from error
    canonical = canonical_evidence_bundle_bytes(bundle)
    if payload != canonical:
        raise ValueError("lab artifact payload must use canonical JSON")
    return bundle


def canonical_evidence_bundle_bytes(bundle: CanonicalEvidenceBundle) -> bytes:
    return (
        json.dumps(
            bundle.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def normalize_persisted_created_at(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("persisted created_at must be timezone-aware")
    return value.astimezone(UTC)


def _reject_nonstandard_json(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")
