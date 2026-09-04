from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "body",
        "filename",
        "hash",
        "header",
        "ip",
        "ip_address",
        "mac",
        "path",
        "payload",
        "port",
        "prompt",
        "sha256",
        "stderr",
        "token_text",
        "uri",
    }
)
_Count = Annotated[int, Field(ge=0, le=20, strict=True)]


class PcapGranularity(StrEnum):
    PACKET = "packet"
    REQUEST = "request"
    FLOW_EVENT = "flow_event"
    LLM_TOKEN = "llm_token"


class PcapAttackCandidate(StrEnum):
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    NONE = "none"


class PcapDetector(StrEnum):
    HTTP_RULE = "http_rule"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    CPD = "cpd"
    SEMANTIC_TOKEN = "semantic_token"


class PcapSupportingSignal(StrEnum):
    SQL_SYNTAX_PATTERN = "sql_syntax_pattern"
    COMMAND_SYNTAX_PATTERN = "command_syntax_pattern"
    PATH_TRAVERSAL_PATTERN = "path_traversal_pattern"
    REQUEST_BOUNDARY = "request_boundary"
    CONNECTION_RATE_INCREASE = "connection_rate_increase"
    DESTINATION_DENSITY_INCREASE = "destination_density_increase"
    CHANGE_POINT_DETECTED = "change_point_detected"
    SEMANTIC_RISK_DETECTED = "semantic_risk_detected"


class _FrozenPcapDetectionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def enforce_public_payload(self) -> _FrozenPcapDetectionModel:
        _assert_public_payload(self.model_dump(mode="json"))
        return self


class PcapLocalizedEvidence(_FrozenPcapDetectionModel):
    evidence_id: str = Field(
        default_factory=lambda: f"evidence_{uuid4().hex}",
        pattern=r"^evidence_[0-9a-f]{32}$",
    )
    granularity: PcapGranularity
    verified_packet_count: int = Field(ge=1, strict=True)
    start_packet: int = Field(ge=1, strict=True)
    end_packet: int = Field(ge=1, strict=True)
    start_offset_ms: int = Field(ge=0, strict=True)
    end_offset_ms: int = Field(ge=0, strict=True)
    attack_candidate: PcapAttackCandidate
    detector: PcapDetector
    confidence: float = Field(ge=0, le=1)
    supporting_signals: tuple[PcapSupportingSignal, ...] = Field(
        min_length=1, max_length=8
    )

    @field_validator("supporting_signals")
    @classmethod
    def require_unique_supporting_signals(
        cls, signals: tuple[PcapSupportingSignal, ...]
    ) -> tuple[PcapSupportingSignal, ...]:
        if len(signals) != len(set(signals)):
            raise ValueError("supporting_signals must be unique")
        return signals

    @model_validator(mode="after")
    def require_ordered_intervals(self) -> PcapLocalizedEvidence:
        if self.start_packet > self.end_packet:
            raise ValueError("start_packet must not exceed end_packet")
        if self.end_packet > self.verified_packet_count:
            raise ValueError("packet interval must not exceed verified_packet_count")
        if self.start_offset_ms > self.end_offset_ms:
            raise ValueError("start_offset_ms must not exceed end_offset_ms")
        return self


class PcapDetectionSummary(_FrozenPcapDetectionModel):
    schema_version: Literal[1] = 1
    analyzed_count: _Count
    succeeded_count: _Count
    failed_count: _Count
    evidence: tuple[PcapLocalizedEvidence, ...] = Field(max_length=160)

    @field_validator("evidence")
    @classmethod
    def require_unique_evidence_ids(
        cls, evidence: tuple[PcapLocalizedEvidence, ...]
    ) -> tuple[PcapLocalizedEvidence, ...]:
        evidence_ids = tuple(item.evidence_id for item in evidence)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence_id values must be unique")
        return evidence

    @model_validator(mode="after")
    def require_consistent_counts(self) -> PcapDetectionSummary:
        if self.succeeded_count + self.failed_count != self.analyzed_count:
            raise ValueError("succeeded_count and failed_count must equal analyzed_count")
        return self


def _normalize_public_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")


def _assert_public_payload(payload: Any) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            normalized_key = _normalize_public_key(key)
            if normalized_key in _FORBIDDEN_PUBLIC_KEYS:
                raise ValueError(
                    f"PCAP detection payload contains forbidden field: {normalized_key}"
                )
            _assert_public_payload(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _assert_public_payload(value)
