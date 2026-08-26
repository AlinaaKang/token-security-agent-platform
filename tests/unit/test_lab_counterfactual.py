from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.lab.counterfactual import CounterfactualRunner
from app.schemas import AnalysisResult


def _result(
    *,
    decision: str = "block",
    risk_score: float = 0.9,
    detector_score: float = 9.0,
    char_start: int | None = 12,
    calibration_version: str = "cal-v2",
    tokenizer_id: str = "qwen-tokenizer",
    system_prompt_hash: str = "sha256:system",
) -> AnalysisResult:
    span = None
    if char_start is not None:
        span = {
            "token_start": 3,
            "token_end": 7,
            "char_start": char_start,
            "char_end": 28,
        }
    return AnalysisResult.model_validate(
        {
            "request_id": "req_fixture",
            "decision": decision,
            "risk_score": risk_score,
            "detector_score": detector_score,
            "detector_status": (
                "token_anomaly_candidate"
                if detector_score >= 5.0
                else "no_token_anomaly"
            ),
            "semantic_severity": "safe",
            "semantic_categories": [],
            "semantic_model_id": "guard-model",
            "semantic_model_version": "guard-v1",
            "semantic_latency_ms": 4.0,
            "semantic_verification": "performed",
            "fusion_reason": "cpd_candidate",
            "suspicious_span": span,
            "signals": [],
            "evidence": [{"source": "entropy_cpd", "summary": "fixture"}],
            "actions": [decision],
            "provenance": {
                "model_id": "qwen-model",
                "tokenizer_id": tokenizer_id,
                "system_prompt_hash": system_prompt_hash,
                "calibration_version": calibration_version,
                "thresholds": {"k": 0.5, "h": 5.0},
            },
            "latency_ms": 30.0,
        }
    )


class RecordingWorkflow:
    def __init__(self, result: AnalysisResult | Exception) -> None:
        self.result = result
        self.calls: list[tuple[object, str]] = []
        self.calibration = SimpleNamespace(model_id="qwen-model")

    def analyze(self, request: object, *, request_id: str) -> AnalysisResult:
        self.calls.append((request, request_id))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_counterfactual_skips_when_cpd_has_no_onset() -> None:
    workflow = RecordingWorkflow(_result(risk_score=0.2, detector_score=1.0))

    result = CounterfactualRunner(workflow).run(
        prompt="A normal question.",
        original=_result(char_start=None),
        mode="analysis",
    )

    assert result.interpretation == "inconclusive"
    assert result.reason == "no_predicted_onset"
    assert result.rechecked is None
    assert workflow.calls == []


@pytest.mark.parametrize("char_start", [0, 18, 99])
def test_counterfactual_rejects_out_of_range_onsets(char_start: int) -> None:
    workflow = RecordingWorkflow(_result(risk_score=0.2, detector_score=1.0))

    result = CounterfactualRunner(workflow).run(
        prompt="A normal question.",
        original=_result(char_start=char_start),
        mode="gateway",
    )

    assert result.interpretation == "inconclusive"
    assert result.reason == "invalid_predicted_onset"
    assert workflow.calls == []


def test_counterfactual_rejects_a_whitespace_only_prefix() -> None:
    workflow = RecordingWorkflow(_result(risk_score=0.2, detector_score=1.0))

    result = CounterfactualRunner(workflow).run(
        prompt="   meaningful continuation",
        original=_result(char_start=3),
        mode="analysis",
    )

    assert result.reason == "invalid_predicted_onset"
    assert workflow.calls == []


def test_counterfactual_rechecks_only_the_prefix_with_knowledge_disabled() -> None:
    workflow = RecordingWorkflow(
        _result(decision="allow", risk_score=0.2, detector_score=1.5, char_start=None)
    )

    result = CounterfactualRunner(workflow).run(
        prompt="Safe prefix. PRIVATE_CONTINUATION",
        original=_result(char_start=12),
        mode="gateway",
    )

    assert len(workflow.calls) == 1
    request, request_id = workflow.calls[0]
    assert request.prompt == "Safe prefix."
    assert request.model_id == "qwen-model"
    assert request.mode == "gateway"
    assert request.knowledge_mode.value == "off"
    assert request_id.startswith("lab_cf_")
    assert result.interpretation == "risk_reduced"
    assert result.reason == "completed"
    assert result.risk_score_delta == pytest.approx(0.7)
    assert result.detector_score_delta == pytest.approx(7.5)
    assert result.action_changed is True
    assert "PRIVATE_CONTINUATION" not in result.model_dump_json()


def test_counterfactual_marks_unchanged_scores_without_claiming_causality() -> None:
    workflow = RecordingWorkflow(
        _result(decision="block", risk_score=0.9, detector_score=9.0, char_start=None)
    )

    result = CounterfactualRunner(workflow).run(
        prompt="Safe prefix. continuation",
        original=_result(char_start=12),
        mode="analysis",
    )

    assert result.interpretation == "unchanged"
    assert result.risk_score_delta == 0.0
    assert result.detector_score_delta == 0.0
    assert result.action_changed is False


def test_counterfactual_requires_matching_provenance() -> None:
    workflow = RecordingWorkflow(
        _result(
            risk_score=0.2,
            detector_score=1.0,
            char_start=None,
            tokenizer_id="different-tokenizer",
        )
    )

    result = CounterfactualRunner(workflow).run(
        prompt="Safe prefix. continuation",
        original=_result(char_start=12),
        mode="analysis",
    )

    assert result.interpretation == "inconclusive"
    assert result.reason == "provenance_mismatch"
    assert result.rechecked is None
    assert result.original.decision == "block"


def test_counterfactual_failure_preserves_the_original_result() -> None:
    workflow = RecordingWorkflow(RuntimeError("PRIVATE_FAILURE_DETAILS"))

    result = CounterfactualRunner(workflow).run(
        prompt="Safe prefix. continuation",
        original=_result(char_start=12),
        mode="analysis",
    )

    assert result.interpretation == "inconclusive"
    assert result.reason == "recheck_failed"
    assert result.rechecked is None
    assert result.original.decision == "block"
    assert "PRIVATE_FAILURE_DETAILS" not in result.model_dump_json()
