from __future__ import annotations

from fastapi.testclient import TestClient

from app.evaluation.pcap_detection import (
    PcapAblationMetrics,
    PcapEvaluationSummary,
)
from app.main import app


def summary() -> PcapEvaluationSummary:
    metrics = PcapAblationMetrics(
        sample_count=2,
        true_positive=1,
        false_positive=0,
        false_negative=0,
        true_negative=1,
        precision=1,
        recall=1,
        f1=1,
        false_positive_rate=0,
        localization_hit_rate=1,
    )
    return PcapEvaluationSummary(
        schema_version=1,
        benchmark_version="pcap-detection-regression-v1",
        dataset_kind="synthetic_sanitized_regression",
        generated_at="2026-09-07T08:00:00Z",
        sample_count=2,
        precision=1,
        recall=1,
        f1=1,
        false_positive_rate=0,
        localization_hit_rate=1,
        ablations={"rule_only": metrics, "behavior_only": metrics, "fused": metrics},
    )


def test_pcap_evaluation_api_returns_validated_summary() -> None:
    app.state.pcap_evaluation_summary = summary()
    try:
        response = TestClient(app).get("/api/v1/evaluation/pcap-summary")
    finally:
        del app.state.pcap_evaluation_summary

    assert response.status_code == 200
    assert response.json()["benchmark_version"] == "pcap-detection-regression-v1"
    assert set(response.json()["ablations"]) == {"rule_only", "behavior_only", "fused"}
    assert "cases" not in response.json()


def test_pcap_evaluation_api_reports_unavailable_without_validated_summary() -> None:
    if hasattr(app.state, "pcap_evaluation_summary"):
        del app.state.pcap_evaluation_summary

    response = TestClient(app).get("/api/v1/evaluation/pcap-summary")

    assert response.status_code == 503
    assert response.json()["detail"] == "pcap evaluation report is unavailable"
