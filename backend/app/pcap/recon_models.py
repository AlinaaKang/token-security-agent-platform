from __future__ import annotations

import math
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.pcap.models import PcapActor, PcapMissionStatus
from scripts.pcap_preflight import ALLOWED_PROTOCOLS


_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "filename",
        "path",
        "ip",
        "port",
        "mac",
        "payload",
        "uri",
        "prompt",
        "token_text",
        "sha256",
        "stderr",
    }
)
_ALLOWED_PROTOCOLS = frozenset(ALLOWED_PROTOCOLS)
_Count = Annotated[int, Field(ge=0, strict=True)]
_ReconTimestamp = Annotated[
    str,
    Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"),
]


class PcapSizeBucket(StrEnum):
    UNDER_2_KIB = "under_2_kib"
    FROM_2_KIB_TO_64_KIB = "2_kib_to_64_kib"
    FROM_64_KIB_TO_1_MIB = "64_kib_to_1_mib"
    AT_LEAST_1_MIB = "at_least_1_mib"


class PcapPacketBucket(StrEnum):
    EMPTY = "empty"
    FROM_1_TO_15 = "1_to_15"
    FROM_16_TO_63 = "16_to_63"
    AT_LEAST_64 = "at_least_64"


class PcapDurationBucket(StrEnum):
    ZERO = "zero"
    UNDER_1_SECOND = "under_1_second"
    FROM_1_TO_10_SECONDS = "1_to_10_seconds"
    OVER_10_SECONDS = "over_10_seconds"


class PcapReconNarrative(StrEnum):
    AUTHORIZATION_ACCEPTED = "authorization_accepted"
    QUARTILE_SAMPLE_SELECTED = "quartile_sample_selected"
    ISOLATED_FULL_CAPTURE_SCAN_RUNNING = "isolated_full_capture_scan_running"
    AGGREGATE_PROFILE_VALIDATED = "aggregate_profile_validated"
    METHOD_SELECTION_CHECKPOINT_READY = "method_selection_checkpoint_ready"


class _FrozenPcapReconPublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def enforce_public_payload(self) -> _FrozenPcapReconPublicModel:
        _assert_public_payload(self.model_dump(mode="json"))
        return self


class PcapQuartileHistogram(_FrozenPcapReconPublicModel):
    quartile_1: _Count
    quartile_2: _Count
    quartile_3: _Count
    quartile_4: _Count


class PcapSizeHistogram(_FrozenPcapReconPublicModel):
    under_2_kib: _Count
    two_kib_to_64_kib: _Count = Field(alias=PcapSizeBucket.FROM_2_KIB_TO_64_KIB)
    sixty_four_kib_to_1_mib: _Count = Field(
        alias=PcapSizeBucket.FROM_64_KIB_TO_1_MIB
    )
    at_least_1_mib: _Count


class PcapPacketHistogram(_FrozenPcapReconPublicModel):
    empty: _Count
    one_to_15: _Count = Field(alias=PcapPacketBucket.FROM_1_TO_15)
    sixteen_to_63: _Count = Field(alias=PcapPacketBucket.FROM_16_TO_63)
    at_least_64: _Count


class PcapDurationHistogram(_FrozenPcapReconPublicModel):
    zero: _Count
    under_1_second: _Count
    one_to_10_seconds: _Count = Field(alias=PcapDurationBucket.FROM_1_TO_10_SECONDS)
    over_10_seconds: _Count


class PcapReconSummary(_FrozenPcapReconPublicModel):
    schema_version: Literal[1] = 1
    sampled_count: _Count = Field(le=20)
    succeeded_count: _Count = Field(le=20)
    failed_count: _Count = Field(le=20)
    quartile_counts: PcapQuartileHistogram
    size_bucket_counts: PcapSizeHistogram
    packet_bucket_counts: PcapPacketHistogram
    duration_bucket_counts: PcapDurationHistogram
    protocol_presence_counts: dict[str, _Count]
    plaintext_sample_count: _Count
    encrypted_sample_count: _Count
    sequence_candidate_count: _Count

    @field_validator("protocol_presence_counts")
    @classmethod
    def require_allowed_protocol_names(
        cls, protocol_presence_counts: dict[str, int]
    ) -> dict[str, int]:
        if set(protocol_presence_counts).difference(_ALLOWED_PROTOCOLS):
            raise ValueError("protocol_presence_counts contains an unsupported protocol")
        return protocol_presence_counts

    @model_validator(mode="after")
    def require_consistent_aggregate_counts(self) -> PcapReconSummary:
        if self.succeeded_count + self.failed_count != self.sampled_count:
            raise ValueError("succeeded_count and failed_count must equal sampled_count")
        if _histogram_total(self.quartile_counts) != self.sampled_count:
            raise ValueError("quartile_counts must equal sampled_count")
        for histogram in (
            self.size_bucket_counts,
            self.packet_bucket_counts,
            self.duration_bucket_counts,
        ):
            if _histogram_total(histogram) != self.succeeded_count:
                raise ValueError("bucket histogram counts must equal succeeded_count")
        counts = (
            *self.quartile_counts.model_dump().values(),
            *self.size_bucket_counts.model_dump().values(),
            *self.packet_bucket_counts.model_dump().values(),
            *self.duration_bucket_counts.model_dump().values(),
            *self.protocol_presence_counts.values(),
            self.plaintext_sample_count,
            self.encrypted_sample_count,
            self.sequence_candidate_count,
        )
        if any(count > self.sampled_count for count in counts):
            raise ValueError("aggregate counts must not exceed sampled_count")
        if any(
            count > self.succeeded_count
            for count in self.protocol_presence_counts.values()
        ):
            raise ValueError("protocol presence counts must not exceed succeeded_count")
        return self


class PcapReconTraceEvent(_FrozenPcapReconPublicModel):
    sequence: int = Field(ge=1, le=10, strict=True)
    actor: PcapActor
    status: Literal["queued", "running", "succeeded", "failed", "skipped"]
    summary: PcapReconNarrative


class PcapReconMissionResult(_FrozenPcapReconPublicModel):
    recon_id: str = Field(pattern=r"^recon_[0-9a-f]{32}$")
    objective: Literal["reconnoiter_pcap_dataset"] = "reconnoiter_pcap_dataset"
    status: PcapMissionStatus
    events: tuple[PcapReconTraceEvent, ...] = Field(max_length=10)
    summary: PcapReconSummary | None = None
    created_at: _ReconTimestamp

    @model_validator(mode="after")
    def require_ordered_events(self) -> PcapReconMissionResult:
        sequences = tuple(event.sequence for event in self.events)
        if sequences != tuple(sorted(sequences)) or len(sequences) != len(set(sequences)):
            raise ValueError("PCAP reconnaissance events must be ordered by sequence")
        return self


class PcapReconOverview(_FrozenPcapReconPublicModel):
    enabled: bool
    max_sample_count: Literal[20] = 20
    max_trace_events: Literal[10] = 10


def bucket_size(size_bytes: int) -> PcapSizeBucket:
    _require_nonnegative_integer(size_bytes, "size_bytes")
    if size_bytes < 2 * 1024:
        return PcapSizeBucket.UNDER_2_KIB
    if size_bytes < 64 * 1024:
        return PcapSizeBucket.FROM_2_KIB_TO_64_KIB
    if size_bytes < 1024 * 1024:
        return PcapSizeBucket.FROM_64_KIB_TO_1_MIB
    return PcapSizeBucket.AT_LEAST_1_MIB


def bucket_packets(packet_count: int) -> PcapPacketBucket:
    _require_nonnegative_integer(packet_count, "packet_count")
    if packet_count == 0:
        return PcapPacketBucket.EMPTY
    if packet_count <= 15:
        return PcapPacketBucket.FROM_1_TO_15
    if packet_count <= 63:
        return PcapPacketBucket.FROM_16_TO_63
    return PcapPacketBucket.AT_LEAST_64


def bucket_duration(duration_seconds: float) -> PcapDurationBucket:
    if (
        isinstance(duration_seconds, bool)
        or not isinstance(duration_seconds, (int, float))
        or not math.isfinite(duration_seconds)
        or duration_seconds < 0
    ):
        raise ValueError("duration_seconds must be a finite nonnegative number")
    if duration_seconds == 0:
        return PcapDurationBucket.ZERO
    if duration_seconds < 1:
        return PcapDurationBucket.UNDER_1_SECOND
    if duration_seconds <= 10:
        return PcapDurationBucket.FROM_1_TO_10_SECONDS
    return PcapDurationBucket.OVER_10_SECONDS


def _histogram_total(histogram: BaseModel) -> int:
    return sum(histogram.model_dump().values())


def _require_nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")


def _assert_public_payload(payload: Any) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in _FORBIDDEN_PUBLIC_KEYS:
                raise ValueError(f"PCAP reconnaissance payload contains forbidden field: {key}")
            _assert_public_payload(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _assert_public_payload(value)
