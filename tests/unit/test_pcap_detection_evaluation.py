from __future__ import annotations

import pytest

from app.evaluation.pcap_detection import (
    PcapEvaluationCase,
    evaluate_pcap_detection,
)
from app.pcap.detection_models import PcapLocalizedEvidence


def evidence(**overrides: object) -> PcapLocalizedEvidence:
    payload: dict[str, object] = {
        "granularity": "request",
        "verified_packet_count": 10,
        "start_packet": 4,
        "end_packet": 5,
        "start_offset_ms": 100,
        "end_offset_ms": 120,
        "attack_candidate": "sql_injection",
        "detector": "http_rule",
        "confidence": 0.9,
        "supporting_signals": ["sql_syntax_pattern", "request_boundary"],
    }
    return PcapLocalizedEvidence.model_validate(payload | overrides)


def test_evaluation_reports_classification_and_localization_metrics() -> None:
    result = evaluate_pcap_detection(
        [
            PcapEvaluationCase(label_risky=True, expected_start_packet=4, expected_end_packet=5, evidence=(evidence(),)),
            PcapEvaluationCase(label_risky=True, expected_start_packet=7, expected_end_packet=7, evidence=()),
            PcapEvaluationCase(label_risky=False, evidence=()),
            PcapEvaluationCase(label_risky=False, evidence=(evidence(),)),
        ]
    )

    assert result.precision == pytest.approx(0.5)
    assert result.recall == pytest.approx(0.5)
    assert result.f1 == pytest.approx(0.5)
    assert result.false_positive_rate == pytest.approx(0.5)
    assert result.localization_hit_rate == pytest.approx(0.5)
    assert result.sample_count == 4


def test_evaluation_exposes_rule_behavior_and_fused_ablations() -> None:
    rule = evidence()
    behavior = evidence(
        detector="behavior_anomaly",
        attack_candidate="command_injection",
        supporting_signals=["connection_rate_increase"],
    )
    result = evaluate_pcap_detection(
        [
            PcapEvaluationCase(label_risky=True, expected_start_packet=4, expected_end_packet=5, evidence=(rule, behavior)),
            PcapEvaluationCase(label_risky=False, evidence=(behavior,)),
        ]
    )

    assert set(result.ablations) == {"rule_only", "behavior_only", "fused"}
    assert result.ablations["rule_only"].true_positive == 1
    assert result.ablations["behavior_only"].false_positive == 1
    assert result.ablations["fused"].precision == pytest.approx(0.5)


def test_evaluation_rejects_missing_expected_interval_for_risky_case() -> None:
    with pytest.raises(ValueError, match="expected packet interval"):
        PcapEvaluationCase(label_risky=True, evidence=())
