from __future__ import annotations

import pytest

from app.detection.calibration import CalibrationMismatchError, CalibrationProfile
from app.detection.cpd import RobustBaseline, fit_system_baseline, run_cpd


def test_robust_baseline_applies_mad_floor_to_constant_sequence() -> None:
    baseline = fit_system_baseline([2.0, 2.0, 2.0, 2.0])

    assert baseline.median == 2.0
    assert baseline.mad_scale == 1e-6


def test_cpd_returns_no_alarm_for_baseline_values() -> None:
    trace = run_cpd(
        [0.0, 0.1, -0.1, 0.0],
        RobustBaseline(median=0.0, mad_scale=1.0),
        k=0.5,
        h=4.0,
    )

    assert trace.alarm_index is None
    assert trace.onset_index is None
    assert trace.score == 0.0


def test_cpd_reports_alarm_and_backtracks_to_nonzero_segment_onset() -> None:
    trace = run_cpd(
        [0.0, 0.0, 3.0, 3.0],
        RobustBaseline(median=0.0, mad_scale=1.0),
        k=0.5,
        h=4.0,
    )

    assert trace.cumulative == pytest.approx((0.0, 0.0, 2.5, 5.0))
    assert trace.alarm_index == 3
    assert trace.onset_index == 2
    assert trace.score == 5.0


def test_cpd_can_reset_after_alarm() -> None:
    trace = run_cpd(
        [3.0, 3.0, 0.0, 3.0, 3.0],
        RobustBaseline(median=0.0, mad_scale=1.0),
        k=0.5,
        h=4.0,
        reset_after_alarm=True,
    )

    assert trace.alarm_indices == (1, 4)
    assert trace.cumulative == pytest.approx((2.5, 0.0, 0.0, 2.5, 0.0))


def test_calibration_profile_rejects_runtime_identity_mismatch() -> None:
    profile = CalibrationProfile(
        version="cal-v1",
        model_id="qwen-model",
        tokenizer_id="qwen-tokenizer",
        system_prompt_hash="sha256:system",
        signal="entropy",
        baseline=RobustBaseline(median=1.0, mad_scale=0.5),
        k=0.5,
        h=8.0,
        created_at="2026-08-25T00:00:00Z",
        dataset_hash="sha256:dataset",
    )

    with pytest.raises(CalibrationMismatchError, match="model_id"):
        profile.ensure_compatible(
            model_id="different-model",
            tokenizer_id="qwen-tokenizer",
            system_prompt_hash="sha256:system",
        )
