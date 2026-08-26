from __future__ import annotations

import uuid
from typing import Any, Literal

from app.lab.models import (
    CounterfactualResult,
    CounterfactualSnapshot,
)
from app.schemas import AnalysisRequest, AnalysisResult


class CounterfactualRunner:
    def __init__(self, workflow: Any) -> None:
        self.workflow = workflow

    def run(
        self,
        *,
        prompt: str,
        original: AnalysisResult,
        mode: Literal["analysis", "gateway"],
    ) -> CounterfactualResult:
        original_snapshot = _snapshot(original)
        char_start = (
            original.suspicious_span.char_start
            if original.suspicious_span is not None
            else None
        )
        if char_start is None:
            return _inconclusive(
                reason="no_predicted_onset",
                char_start=None,
                original=original,
                snapshot=original_snapshot,
            )
        if char_start <= 0 or char_start >= len(prompt):
            return _inconclusive(
                reason="invalid_predicted_onset",
                char_start=char_start,
                original=original,
                snapshot=original_snapshot,
            )

        prefix = prompt[:char_start]
        if not prefix.strip():
            return _inconclusive(
                reason="invalid_predicted_onset",
                char_start=char_start,
                original=original,
                snapshot=original_snapshot,
            )

        try:
            rechecked = self.workflow.analyze(
                AnalysisRequest(
                    prompt=prefix,
                    model_id=original.provenance.model_id,
                    mode=mode,
                    knowledge_mode="off",
                ),
                request_id=f"lab_cf_{uuid.uuid4().hex}",
            )
        except Exception:
            return _inconclusive(
                reason="recheck_failed",
                char_start=char_start,
                original=original,
                snapshot=original_snapshot,
            )

        if _provenance_key(rechecked) != _provenance_key(original):
            return _inconclusive(
                reason="provenance_mismatch",
                char_start=char_start,
                original=original,
                snapshot=original_snapshot,
            )

        risk_delta = original.risk_score - rechecked.risk_score
        detector_delta = original.detector_score - rechecked.detector_score
        interpretation = (
            "risk_reduced"
            if risk_delta > 1e-6 or detector_delta > 1e-6
            else "unchanged"
        )
        return CounterfactualResult(
            interpretation=interpretation,
            reason="completed",
            char_start=char_start,
            calibration_version=original.provenance.calibration_version,
            original=original_snapshot,
            rechecked=_snapshot(rechecked),
            risk_score_delta=risk_delta,
            detector_score_delta=detector_delta,
            action_changed=original.decision != rechecked.decision,
        )


def _snapshot(result: AnalysisResult) -> CounterfactualSnapshot:
    return CounterfactualSnapshot(
        semantic_severity=result.semantic_severity,
        detector_status=result.detector_status,
        risk_score=result.risk_score,
        detector_score=result.detector_score,
        decision=result.decision,
        latency_ms=result.latency_ms,
    )


def _provenance_key(result: AnalysisResult) -> tuple[object, ...]:
    provenance = result.provenance
    return (
        provenance.model_id,
        provenance.tokenizer_id,
        provenance.system_prompt_hash,
        provenance.calibration_version,
        tuple(sorted(provenance.thresholds.items())),
    )


def _inconclusive(
    *,
    reason: Literal[
        "no_predicted_onset",
        "invalid_predicted_onset",
        "provenance_mismatch",
        "recheck_failed",
    ],
    char_start: int | None,
    original: AnalysisResult,
    snapshot: CounterfactualSnapshot,
) -> CounterfactualResult:
    return CounterfactualResult(
        interpretation="inconclusive",
        reason=reason,
        char_start=char_start,
        calibration_version=original.provenance.calibration_version,
        original=snapshot,
    )
