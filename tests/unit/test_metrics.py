from __future__ import annotations

import pytest

from app.detection.baselines import global_nll_score, windowed_nll_score
from app.evaluation.metrics import (
    binary_metrics,
    latency_metrics,
    localization_metrics,
)
from app.evaluation.runner import PredictionIdentityError, validate_prediction_ids


def test_global_and_windowed_nll_baselines_use_expected_aggregation() -> None:
    nll = [1.0, 2.0, 6.0]

    assert global_nll_score(nll) == pytest.approx(3.0)
    assert windowed_nll_score(nll, window_size=1) == pytest.approx(6.0)
    assert windowed_nll_score(nll, window_size=2) == pytest.approx(4.0)


def test_binary_metrics_match_hand_computed_fixture() -> None:
    metrics = binary_metrics(
        labels=[False, False, True, True],
        scores=[0.1, 0.4, 0.35, 0.8],
        threshold=0.5,
    )

    assert metrics.f1 == pytest.approx(2 / 3)
    assert metrics.auroc == pytest.approx(0.75)
    assert metrics.false_positive_rate == 0.0


def test_localization_metrics_measure_distance_and_suffix_hits() -> None:
    metrics = localization_metrics(
        suffix_starts=[10, 20],
        suffix_ends=[15, 25],
        predicted_onsets=[12, 18],
    )

    assert metrics.onset_mae == pytest.approx(2.0)
    assert metrics.trigger_in_suffix_rate == pytest.approx(0.5)


def test_latency_metrics_use_interpolated_percentiles() -> None:
    metrics = latency_metrics([10.0, 20.0, 30.0, 40.0])

    assert metrics.p50_ms == pytest.approx(25.0)
    assert metrics.p95_ms == pytest.approx(38.5)


def test_runner_rejects_predictions_outside_frozen_manifest() -> None:
    with pytest.raises(PredictionIdentityError, match="unknown"):
        validate_prediction_ids(
            prediction_ids={"sample-1", "sample-unknown"},
            manifest_ids={"sample-1", "sample-2"},
        )
