from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.pcap.recon_models import (
    PcapDurationBucket,
    PcapPacketBucket,
    PcapReconMissionResult,
    PcapReconOverview,
    PcapReconSummary,
    PcapSizeBucket,
    bucket_duration,
    bucket_packets,
    bucket_size,
)


def public_summary_payload() -> dict[str, object]:
    return {
        "sampled_count": 4,
        "succeeded_count": 3,
        "failed_count": 1,
        "quartile_counts": {
            "quartile_1": 1,
            "quartile_2": 1,
            "quartile_3": 1,
            "quartile_4": 1,
        },
        "size_bucket_counts": {
            "under_2_kib": 1,
            "2_kib_to_64_kib": 1,
            "64_kib_to_1_mib": 1,
            "at_least_1_mib": 0,
        },
        "packet_bucket_counts": {
            "empty": 1,
            "1_to_15": 1,
            "16_to_63": 1,
            "at_least_64": 0,
        },
        "duration_bucket_counts": {
            "zero": 1,
            "under_1_second": 1,
            "1_to_10_seconds": 1,
            "over_10_seconds": 0,
        },
        "protocol_presence_counts": {"dns": 2, "tls": 1},
        "plaintext_sample_count": 1,
        "encrypted_sample_count": 1,
        "sequence_candidate_count": 1,
    }


def public_mission_payload() -> dict[str, object]:
    return {
        "recon_id": "recon_0123456789abcdef0123456789abcdef",
        "status": "completed",
        "events": [
            {
                "sequence": 1,
                "actor": "coordinator",
                "status": "succeeded",
                "summary": "aggregate_profile_validated",
            }
        ],
        "summary": public_summary_payload(),
        "created_at": "2026-09-03T00:00:00Z",
    }


def test_recon_buckets_have_closed_boundaries() -> None:
    assert bucket_size(2047) is PcapSizeBucket.UNDER_2_KIB
    assert bucket_size(2048) is PcapSizeBucket.FROM_2_KIB_TO_64_KIB
    assert bucket_size(65536) is PcapSizeBucket.FROM_64_KIB_TO_1_MIB
    assert bucket_size(1048576) is PcapSizeBucket.AT_LEAST_1_MIB
    assert bucket_packets(0) is PcapPacketBucket.EMPTY
    assert bucket_packets(15) is PcapPacketBucket.FROM_1_TO_15
    assert bucket_packets(16) is PcapPacketBucket.FROM_16_TO_63
    assert bucket_packets(64) is PcapPacketBucket.AT_LEAST_64
    assert bucket_duration(0.0) is PcapDurationBucket.ZERO
    assert bucket_duration(0.999999) is PcapDurationBucket.UNDER_1_SECOND
    assert bucket_duration(1.0) is PcapDurationBucket.FROM_1_TO_10_SECONDS
    assert bucket_duration(10.0) is PcapDurationBucket.FROM_1_TO_10_SECONDS
    assert bucket_duration(10.000001) is PcapDurationBucket.OVER_10_SECONDS


@pytest.mark.parametrize(
    "private_key",
    [
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
    ],
)
@pytest.mark.parametrize(
    "nested_path",
    [
        (),
        ("quartile_counts",),
        ("size_bucket_counts",),
        ("packet_bucket_counts",),
        ("duration_bucket_counts",),
    ],
)
def test_recon_summary_rejects_private_fields_at_every_public_level(
    private_key: str, nested_path: tuple[str, ...]
) -> None:
    payload = public_summary_payload()
    target = payload
    for field in nested_path:
        target = target[field]  # type: ignore[assignment,index]
    target[private_key] = "PRIVATE_SENTINEL"

    with pytest.raises(ValidationError):
        PcapReconSummary.model_validate(payload)


@pytest.mark.parametrize(
    "private_key",
    [
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
    ],
)
@pytest.mark.parametrize("nested_path", [(), ("events", 0), ("summary",)])
def test_recon_mission_rejects_private_fields_at_every_public_level(
    private_key: str, nested_path: tuple[str | int, ...]
) -> None:
    payload = public_mission_payload()
    target = payload
    for field in nested_path:
        target = target[field]  # type: ignore[assignment,index]
    target[private_key] = "PRIVATE_SENTINEL"

    with pytest.raises(ValidationError):
        PcapReconMissionResult.model_validate(payload)


@pytest.mark.parametrize("private_key", ["filename", "path", "ip", "payload", "stderr"])
def test_recon_overview_rejects_private_fields(private_key: str) -> None:
    with pytest.raises(ValidationError):
        PcapReconOverview.model_validate(
            {"enabled": True, private_key: "PRIVATE_SENTINEL"}
        )


@pytest.mark.parametrize(
    "summary_update",
    [
        {"succeeded_count": 2},
        {"plaintext_sample_count": 5},
        {"protocol_presence_counts": {"dns": 4}},
        {"protocol_presence_counts": {"smtp": 1}},
        {
            "size_bucket_counts": {
                "under_2_kib": 5,
                "2_kib_to_64_kib": 1,
                "64_kib_to_1_mib": 0,
                "at_least_1_mib": 0,
            }
        },
    ],
)
def test_recon_summary_rejects_inconsistent_aggregate_counts(
    summary_update: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        PcapReconSummary.model_validate(public_summary_payload() | summary_update)


def test_recon_mission_has_closed_identifier_trace_and_objective_contract() -> None:
    result = PcapReconMissionResult.model_validate(public_mission_payload())

    assert result.objective == "reconnoiter_pcap_dataset"
    assert result.recon_id == "recon_0123456789abcdef0123456789abcdef"
    with pytest.raises(ValidationError):
        PcapReconMissionResult.model_validate(
            public_mission_payload() | {"recon_id": "mission_" + "a" * 32}
        )


def test_recon_summary_accepts_partial_histograms_for_incomplete_scans() -> None:
    payload = public_summary_payload() | {
        "quartile_counts": {
            "quartile_1": 0,
            "quartile_2": 0,
            "quartile_3": 0,
            "quartile_4": 0,
        },
        "size_bucket_counts": {
            "under_2_kib": 0,
            "2_kib_to_64_kib": 0,
            "64_kib_to_1_mib": 0,
            "at_least_1_mib": 0,
        },
        "packet_bucket_counts": {
            "empty": 0,
            "1_to_15": 0,
            "16_to_63": 0,
            "at_least_64": 0,
        },
        "duration_bucket_counts": {
            "zero": 0,
            "under_1_second": 0,
            "1_to_10_seconds": 0,
            "over_10_seconds": 0,
        },
    }

    summary = PcapReconSummary.model_validate(payload)

    assert summary.sampled_count == 4
    with pytest.raises(ValidationError):
        PcapReconMissionResult.model_validate(
            public_mission_payload()
            | {
                "events": [
                    {
                        "sequence": index,
                        "actor": "coordinator",
                        "status": "succeeded",
                        "summary": "aggregate_profile_validated",
                    }
                    for index in range(1, 12)
                ]
            }
        )
