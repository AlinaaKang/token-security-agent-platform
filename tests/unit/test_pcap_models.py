from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.pcap.models import (
    PcapAuthorizationReceipt,
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
                "summary": "batch_triage_completed",
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
            "confirmed": ["encrypted_transport_observed"],
            "candidates": [],
            "unknowns": [],
            "recommended_action": ["retain_public_metadata"],
        },
        "limitations": ["no_packet_payload_retained"],
        "created_at": "2026-09-01T00:00:00Z",
    }


def public_authorization_receipt_payload() -> dict[str, object]:
    return {
        "receipt_id": "pcap_auth_receipt_0123456789abcdef0123456789abcdef",
        "request_id": "pcap_auth_request_0123456789abcdef0123456789abcdef",
        "batch_id": "batch_0123456789abcdef0123456789abcdef",
        "status": "authorized",
        "authorized_capture_ids": [
            "capture_0123456789abcdef0123456789abcdef",
        ],
        "issued_at": "2026-09-01T00:00:00Z",
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


def test_capture_evidence_rejects_token_eligible_without_plaintext_visibility() -> None:
    payload = public_capture_payload() | {"capability": "token_eligible"}

    with pytest.raises(ValidationError, match="token_eligible"):
        PcapCaptureEvidence.model_validate(payload)


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


def test_batch_summary_rejects_counts_that_contradict_capture_statuses() -> None:
    payload = {
        "batch_id": "batch_0123456789abcdef0123456789abcdef",
        "selected_count": 1,
        "succeeded_count": 0,
        "failed_count": 1,
        "skipped_count": 0,
        "captures": [public_capture_payload()],
    }

    with pytest.raises(ValidationError, match="capture statuses"):
        PcapBatchSummary.model_validate(payload)


@pytest.mark.parametrize("private_identifier", ["capture.pcap", r"C:\\private\\capture.pcap"])
def test_authorization_receipt_rejects_non_public_capture_identifiers(
    private_identifier: str,
) -> None:
    payload = public_authorization_receipt_payload() | {
        "authorized_capture_ids": [private_identifier]
    }

    with pytest.raises(ValidationError):
        PcapAuthorizationReceipt.model_validate(payload)


@pytest.mark.parametrize(
    "private_narrative",
    [
        "capture.pcap",
        r"C:\\quarantine\\input\\capture.pcap",
        "203.0.113.10:443",
        "aa:bb:cc:dd:ee:ff",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "raw packet payload",
        "original Prompt text",
        "adversarial suffix",
        "Token text",
        "raw stderr: access denied",
        "hidden reasoning: private",
    ],
)
def test_public_narrative_rejects_sensitive_capture_content(
    private_narrative: str,
) -> None:
    with pytest.raises(ValidationError):
        PcapTraceEvent.model_validate(
            {
                "sequence": 1,
                "actor": "coordinator",
                "status": "succeeded",
                "summary": private_narrative,
            }
        )


@pytest.mark.parametrize("private_narrative", ["capture.pcap", "203.0.113.10:443"])
def test_mission_report_and_limitations_reject_sensitive_narratives(
    private_narrative: str,
) -> None:
    report_payload = public_mission_payload() | {
        "report": {
            "confirmed": [private_narrative],
            "candidates": [],
            "unknowns": [],
            "recommended_action": [],
        }
    }
    limitation_payload = public_mission_payload() | {
        "limitations": [private_narrative]
    }

    with pytest.raises(ValidationError):
        PcapMissionResult.model_validate(report_payload)
    with pytest.raises(ValidationError):
        PcapMissionResult.model_validate(limitation_payload)


def test_mission_result_requires_ordered_public_events_and_fixed_report_sections() -> None:
    payload = public_mission_payload()

    result = PcapMissionResult.model_validate(payload)

    assert result.status is PcapMissionStatus.COMPLETED
    assert result.events[0].sequence == 1
    assert result.report.confirmed == ("encrypted_transport_observed",)
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
                        "summary": "batch_triage_completed",
                    },
                    {
                        "sequence": 1,
                        "actor": "knowledge_analyst",
                        "status": "succeeded",
                        "summary": "batch_triage_completed",
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
