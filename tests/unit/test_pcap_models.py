from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.pcap.models import (
    PcapBatchSummary,
    PcapCaptureEvidence,
    PcapMissionResult,
    PcapMissionStatus,
    PcapToolId,
    PcapTraceEvent,
)


def public_capture_payload() -> dict[str, object]:
    return {
        "capture_id": "capture_0123456789abcdef0123456789abcdef",
        "status": "succeeded",
        "packet_count": 4,
        "protocol_counts": {"dns": 1, "tls": 3},
        "visibility": {
            "plaintext_application_protocol_observed": False,
            "encrypted_transport_observed": True,
            "tls_observed": True,
            "quic_observed": False,
        },
        "capability": "traffic_only",
    }


def public_mission_payload() -> dict[str, object]:
    capture = public_capture_payload()
    return {
        "mission_id": "mission_0123456789abcdef0123456789abcdef",
        "objective": "triage_pcap_evidence",
        "status": "completed",
        "batch_id": "batch_0123456789abcdef0123456789abcdef",
        "events": [
            {
                "sequence": 1,
                "actor": "coordinator",
                "status": "succeeded",
                "summary": "Authorized batch triage completed.",
            }
        ],
        "summary": {
            "batch_id": "batch_0123456789abcdef0123456789abcdef",
            "selected_count": 1,
            "succeeded_count": 1,
            "failed_count": 0,
            "skipped_count": 0,
            "captures": [capture],
        },
        "report": {
            "confirmed": ["Encrypted transport observed."],
            "candidates": [],
            "unknowns": [],
            "recommended_action": ["Retain only public metadata."],
        },
        "limitations": ["No packet payload was retained."],
        "created_at": "2026-09-01T00:00:00Z",
    }


@pytest.mark.parametrize(
    "private_key", ["filename", "path", "sha256", "prompt", "payload", "token_text"]
)
def test_public_capture_evidence_rejects_private_keys(private_key: str) -> None:
    payload = public_capture_payload() | {private_key: "PRIVATE_SENTINEL"}

    with pytest.raises(ValidationError):
        PcapCaptureEvidence.model_validate(payload)


@pytest.mark.parametrize(
    "protocol_counts",
    [
        {"smtp": 1},
        {"dns": -1},
        {"dns": True},
    ],
)
def test_capture_evidence_rejects_unknown_or_non_count_protocols(
    protocol_counts: dict[str, int]
) -> None:
    payload = public_capture_payload() | {"protocol_counts": protocol_counts}

    with pytest.raises(ValidationError):
        PcapCaptureEvidence.model_validate(payload)


def test_capture_evidence_is_immutable_and_serializes_only_public_fields() -> None:
    evidence = PcapCaptureEvidence.model_validate(public_capture_payload())

    serialized = evidence.model_dump(mode="json")
    assert serialized["capture_id"] == "capture_0123456789abcdef0123456789abcdef"
    assert not {
        "filename",
        "path",
        "sha256",
        "prompt",
        "payload",
        "token_text",
    }.intersection(serialized)
    with pytest.raises(ValidationError):
        evidence.packet_count = 99


def test_batch_summary_limits_captures_to_twenty() -> None:
    capture = public_capture_payload()
    payload = {
        "batch_id": "batch_0123456789abcdef0123456789abcdef",
        "selected_count": 20,
        "succeeded_count": 20,
        "failed_count": 0,
        "skipped_count": 0,
        "captures": [capture] * 21,
    }

    with pytest.raises(ValidationError):
        PcapBatchSummary.model_validate(payload)


def test_mission_result_requires_ordered_public_events_and_fixed_report_sections() -> None:
    payload = public_mission_payload()

    result = PcapMissionResult.model_validate(payload)

    assert result.status is PcapMissionStatus.COMPLETED
    assert result.events[0].sequence == 1
    assert result.report.confirmed == ("Encrypted transport observed.",)
    assert PcapToolId.PCAP_BATCH_TRIAGE.value == "pcap_batch_triage"

    with pytest.raises(ValidationError, match="ordered"):
        PcapMissionResult.model_validate(
            payload
            | {
                "events": [
                    {
                        "sequence": 2,
                        "actor": "coordinator",
                        "status": "succeeded",
                        "summary": "Second public event.",
                    },
                    {
                        "sequence": 1,
                        "actor": "knowledge_analyst",
                        "status": "succeeded",
                        "summary": "First public event.",
                    },
                ]
            }
        )
    partial_report = PcapMissionResult.model_validate(
        payload | {"report": {"confirmed": [], "candidates": []}}
    )
    assert partial_report.report.model_dump(mode="json") == {
        "confirmed": [],
        "candidates": [],
        "unknowns": [],
        "recommended_action": [],
    }


def test_trace_event_rejects_private_fields_and_sequence_over_twelve() -> None:
    with pytest.raises(ValidationError):
        PcapTraceEvent.model_validate(
            {
                "sequence": 13,
                "actor": "network_evidence_analyst",
                "status": "succeeded",
                "summary": "Out of bounds.",
                "payload": "PRIVATE_SENTINEL",
            }
        )
