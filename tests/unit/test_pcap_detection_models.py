from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.pcap.detection_models import (
    PcapAttackCandidate,
    PcapDetectionSummary,
    PcapDetector,
    PcapGranularity,
    PcapLocalizedEvidence,
    PcapSupportingSignal,
)


def evidence_payload() -> dict[str, object]:
    return {
        "granularity": "request",
        "verified_packet_count": 12,
        "start_packet": 4,
        "end_packet": 7,
        "start_offset_ms": 120,
        "end_offset_ms": 260,
        "attack_candidate": "sql_injection",
        "detector": "http_rule",
        "confidence": 0.91,
        "supporting_signals": ["sql_syntax_pattern", "request_boundary"],
    }


def summary_payload() -> dict[str, object]:
    return {
        "analyzed_count": 2,
        "succeeded_count": 1,
        "failed_count": 1,
        "evidence": [evidence_payload()],
    }


def test_localized_evidence_accepts_request_and_packet_intervals() -> None:
    request = PcapLocalizedEvidence.model_validate(evidence_payload())
    packet = PcapLocalizedEvidence.model_validate(
        evidence_payload()
        | {
            "granularity": "packet",
            "start_packet": 9,
            "end_packet": 9,
            "start_offset_ms": 400,
            "end_offset_ms": 400,
            "attack_candidate": "path_traversal",
            "supporting_signals": ["path_traversal_pattern"],
        }
    )

    assert request.granularity is PcapGranularity.REQUEST
    assert request.attack_candidate is PcapAttackCandidate.SQL_INJECTION
    assert request.detector is PcapDetector.HTTP_RULE
    assert request.supporting_signals == (
        PcapSupportingSignal.SQL_SYNTAX_PATTERN,
        PcapSupportingSignal.REQUEST_BOUNDARY,
    )
    assert packet.start_packet == packet.end_packet == 9


def test_localized_evidence_generates_a_random_public_identifier() -> None:
    first = PcapLocalizedEvidence.model_validate(evidence_payload())
    second = PcapLocalizedEvidence.model_validate(evidence_payload())

    assert first.evidence_id.startswith("evidence_")
    assert len(first.evidence_id) == len("evidence_") + 32
    assert first.evidence_id != second.evidence_id


@pytest.mark.parametrize(
    "update",
    [
        {"start_packet": 0},
        {"start_packet": 8, "end_packet": 7},
        {"verified_packet_count": 6},
        {"start_offset_ms": -1},
        {"start_offset_ms": 261, "end_offset_ms": 260},
        {"confidence": -0.01},
        {"confidence": 1.01},
        {"supporting_signals": []},
        {"supporting_signals": ["request_boundary", "request_boundary"]},
    ],
)
def test_localized_evidence_rejects_invalid_bounds(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        PcapLocalizedEvidence.model_validate(evidence_payload() | update)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("granularity", "byte"),
        ("attack_candidate", "port_scan"),
        ("detector", "suricata_guess"),
        ("supporting_signals", ["raw_payload_match"]),
    ],
)
def test_localized_evidence_rejects_values_outside_closed_enums(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        PcapLocalizedEvidence.model_validate(evidence_payload() | {field: value})


@pytest.mark.parametrize(
    "private_key",
    [
        "filename",
        "path",
        "ip",
        "ip_address",
        "port",
        "mac",
        "payload",
        "uri",
        "header",
        "body",
        "hash",
        "stderr",
        "Prompt",
        "token_text",
    ],
)
@pytest.mark.parametrize("nested_path", [(), ("evidence", 0)])
def test_detection_summary_rejects_private_fields_recursively(
    private_key: str, nested_path: tuple[str | int, ...]
) -> None:
    payload = summary_payload()
    target = payload
    for segment in nested_path:
        target = target[segment]  # type: ignore[assignment,index]
    target[private_key] = "PRIVATE_SENTINEL"

    with pytest.raises(ValidationError):
        PcapDetectionSummary.model_validate(payload)


def test_detection_summary_requires_consistent_counts_and_unique_evidence() -> None:
    summary = PcapDetectionSummary.model_validate(summary_payload())
    assert summary.analyzed_count == 2
    assert len(summary.evidence) == 1

    with pytest.raises(ValidationError):
        PcapDetectionSummary.model_validate(summary_payload() | {"failed_count": 0})

    duplicate = evidence_payload() | {
        "evidence_id": "evidence_0123456789abcdef0123456789abcdef"
    }
    with pytest.raises(ValidationError):
        PcapDetectionSummary.model_validate(
            summary_payload() | {"evidence": [duplicate, duplicate]}
        )
