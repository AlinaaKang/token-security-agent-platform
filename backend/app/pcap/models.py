from __future__ import annotations

from collections import Counter
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scripts.pcap_preflight import ALLOWED_PROTOCOLS


_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {"filename", "path", "sha256", "prompt", "payload", "token_text"}
)
_ALLOWED_PROTOCOLS = frozenset(ALLOWED_PROTOCOLS)
_ProtocolCount = Annotated[int, Field(ge=0, strict=True)]
_CaptureId = Annotated[str, Field(pattern=r"^capture_[0-9a-f]{32}$")]
_PcapTimestamp = Annotated[
    str,
    Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"),
]


class PcapCapability(StrEnum):
    TOKEN_ELIGIBLE = "token_eligible"
    TRAFFIC_ONLY = "traffic_only"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class PcapMissionStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    DEGRADED = "degraded"


class PcapToolId(StrEnum):
    PCAP_BATCH_TRIAGE = "pcap_batch_triage"


class PcapActor(StrEnum):
    COORDINATOR = "coordinator"
    NETWORK_EVIDENCE_ANALYST = "network_evidence_analyst"
    KNOWLEDGE_ANALYST = "knowledge_analyst"
    RESPONSE_OPERATOR = "response_operator"


class PcapPublicNarrative(StrEnum):
    BATCH_TRIAGE_COMPLETED = "batch_triage_completed"
    ENCRYPTED_TRANSPORT_OBSERVED = "encrypted_transport_observed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NO_PACKET_PAYLOAD_RETAINED = "no_packet_payload_retained"
    PLAINTEXT_APPLICATION_PROTOCOL_OBSERVED = "plaintext_application_protocol_observed"
    RETAIN_PUBLIC_METADATA = "retain_public_metadata"
    TRAFFIC_ONLY_EVIDENCE = "traffic_only_evidence"


class _FrozenPcapPublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def enforce_public_payload(self) -> _FrozenPcapPublicModel:
        _assert_public_payload(self.model_dump(mode="json"))
        return self


class PcapVisibility(_FrozenPcapPublicModel):
    plaintext_application_protocol_observed: bool
    encrypted_transport_observed: bool
    tls_observed: bool
    quic_observed: bool


class PcapCaptureEvidence(_FrozenPcapPublicModel):
    capture_id: _CaptureId
    status: Literal["succeeded", "failed", "skipped"]
    packet_count: int = Field(ge=0, strict=True)
    protocol_counts: dict[str, _ProtocolCount]
    visibility: PcapVisibility
    capability: PcapCapability | None = None
    error_code: str | None = Field(default=None, pattern=r"^[a-z0-9_]+$")

    @field_validator("protocol_counts")
    @classmethod
    def require_allowed_protocol_names(
        cls, protocol_counts: dict[str, int]
    ) -> dict[str, int]:
        unknown = set(protocol_counts).difference(_ALLOWED_PROTOCOLS)
        if unknown:
            raise ValueError("protocol_counts contains an unsupported protocol")
        return protocol_counts

    @model_validator(mode="after")
    def require_capability_visibility_consistency(self) -> PcapCaptureEvidence:
        if (
            self.capability is PcapCapability.TOKEN_ELIGIBLE
            and not self.visibility.plaintext_application_protocol_observed
        ):
            raise ValueError("token_eligible requires plaintext application visibility")
        return self


class PcapBatchSummary(_FrozenPcapPublicModel):
    schema_version: Literal[1] = 1
    batch_id: str = Field(pattern=r"^batch_[0-9a-f]{32}$")
    selected_count: int = Field(ge=0, le=20, strict=True)
    succeeded_count: int = Field(ge=0, le=20, strict=True)
    failed_count: int = Field(ge=0, le=20, strict=True)
    skipped_count: int = Field(ge=0, le=20, strict=True)
    captures: tuple[PcapCaptureEvidence, ...] = Field(max_length=20)

    @model_validator(mode="after")
    def require_consistent_capture_counts(self) -> PcapBatchSummary:
        if self.selected_count != len(self.captures):
            raise ValueError("selected_count must match the number of captures")
        if self.selected_count != (
            self.succeeded_count + self.failed_count + self.skipped_count
        ):
            raise ValueError("capture status counts must equal selected_count")
        actual_counts = Counter(capture.status for capture in self.captures)
        if (
            self.succeeded_count,
            self.failed_count,
            self.skipped_count,
        ) != (
            actual_counts["succeeded"],
            actual_counts["failed"],
            actual_counts["skipped"],
        ):
            raise ValueError("capture statuses must match aggregate counts")
        return self


class PcapAuthorizationRequest(_FrozenPcapPublicModel):
    request_id: str = Field(pattern=r"^pcap_auth_request_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^batch_[0-9a-f]{32}$")
    requested_by: PcapActor
    capture_ids: tuple[_CaptureId, ...] = Field(min_length=1, max_length=20)
    created_at: _PcapTimestamp

    @field_validator("capture_ids")
    @classmethod
    def require_unique_capture_identifiers(
        cls, capture_ids: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(capture_ids) != len(set(capture_ids)):
            raise ValueError("capture_ids must be unique public capture identifiers")
        return capture_ids


class PcapAuthorizationReceipt(_FrozenPcapPublicModel):
    receipt_id: str = Field(pattern=r"^pcap_auth_receipt_[0-9a-f]{32}$")
    request_id: str = Field(pattern=r"^pcap_auth_request_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^batch_[0-9a-f]{32}$")
    status: Literal["authorized", "denied"]
    authorized_capture_ids: tuple[_CaptureId, ...] = Field(max_length=20)
    issued_at: _PcapTimestamp

    @field_validator("authorized_capture_ids")
    @classmethod
    def require_unique_capture_identifiers(
        cls, capture_ids: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(capture_ids) != len(set(capture_ids)):
            raise ValueError("authorized_capture_ids must be unique public capture identifiers")
        return capture_ids


class PcapTraceEvent(_FrozenPcapPublicModel):
    sequence: int = Field(ge=1, le=12, strict=True)
    actor: PcapActor
    status: Literal["queued", "running", "succeeded", "failed", "skipped"]
    summary: PcapPublicNarrative
    tool_id: PcapToolId | None = None


class PcapMissionReport(_FrozenPcapPublicModel):
    confirmed: tuple[PcapPublicNarrative, ...] = ()
    candidates: tuple[PcapPublicNarrative, ...] = ()
    unknowns: tuple[PcapPublicNarrative, ...] = ()
    recommended_action: tuple[PcapPublicNarrative, ...] = ()


class PcapMissionResult(_FrozenPcapPublicModel):
    mission_id: str = Field(pattern=r"^mission_[0-9a-f]{32}$")
    objective: Literal["triage_pcap_evidence"] = "triage_pcap_evidence"
    status: PcapMissionStatus
    batch_id: str = Field(pattern=r"^batch_[0-9a-f]{32}$")
    events: tuple[PcapTraceEvent, ...] = Field(max_length=12)
    summary: PcapBatchSummary | None = None
    report: PcapMissionReport
    limitations: tuple[PcapPublicNarrative, ...] = Field(min_length=1, max_length=4)
    created_at: _PcapTimestamp

    @model_validator(mode="after")
    def require_ordered_events_and_matching_summary(self) -> PcapMissionResult:
        sequences = tuple(event.sequence for event in self.events)
        if sequences != tuple(sorted(sequences)) or len(sequences) != len(set(sequences)):
            raise ValueError("PCAP mission events must be ordered by sequence")
        if self.summary is not None and self.summary.batch_id != self.batch_id:
            raise ValueError("PCAP mission summary must match batch_id")
        return self


class PcapOverview(_FrozenPcapPublicModel):
    enabled: bool
    tool_id: PcapToolId = PcapToolId.PCAP_BATCH_TRIAGE
    max_batch_size: Literal[20] = 20
    max_trace_events: Literal[12] = 12
    actors: tuple[PcapActor, ...] = tuple(PcapActor)


def _assert_public_payload(payload: Any) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in _FORBIDDEN_PUBLIC_KEYS:
                raise ValueError(f"PCAP payload contains forbidden field: {key}")
            _assert_public_payload(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _assert_public_payload(value)
