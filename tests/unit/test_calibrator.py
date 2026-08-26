from __future__ import annotations

import pytest

from app.detection.calibrator import (
    calibrate_entropy,
    select_candidate_by_dev,
    select_f1_threshold,
    select_threshold_at_max_fpr,
)
from app.detection.calibration import CalibrationProfile
from app.detection.cpd import RobustBaseline
from app.model.runtime import ModelObservation
from app.model.token_stats import ObservedUserToken


def make_observation(
    entropies: list[float],
    *,
    system_entropies: tuple[float, ...] = (0.5, 1.0, 1.5),
) -> ModelObservation:
    return ModelObservation(
        model_id="qwen-model",
        tokenizer_id="qwen-tokenizer",
        system_prompt_hash="sha256:system",
        system_entropies=system_entropies,
        user_tokens=tuple(
            ObservedUserToken(
                user_index=index,
                full_index=index + 1,
                token_id=index + 10,
                token_text=f"token-{index}",
                char_start=index,
                char_end=index + 1,
                entropy=entropy,
                nll=1.0,
            )
            for index, entropy in enumerate(entropies)
        ),
        latency_ms=1.0,
    )


def test_select_f1_threshold_maximizes_f1() -> None:
    assert select_f1_threshold(
        labels=[False, False, True, True],
        scores=[0.1, 0.2, 0.8, 0.9],
    ) == pytest.approx(0.8)


def test_select_f1_threshold_breaks_ties_by_lower_fpr() -> None:
    threshold = select_f1_threshold(
        labels=[True, False, False, True],
        scores=[0.1, 0.2, 0.3, 0.4],
    )

    assert threshold == pytest.approx(0.4)


def test_select_f1_threshold_requires_both_classes() -> None:
    with pytest.raises(ValueError, match="both classes"):
        select_f1_threshold(labels=[True, True], scores=[1.0, 2.0])


def test_select_threshold_at_max_fpr_uses_highest_recall_feasible_point() -> None:
    threshold = select_threshold_at_max_fpr(
        labels=[False, False, True, True],
        scores=[0.1, 0.6, 0.7, 0.9],
        max_fpr=0.0,
    )

    assert threshold == pytest.approx(0.7)


def test_calibration_uses_system_entropy_and_labeled_prompt_scores() -> None:
    profile = calibrate_entropy(
        [make_observation([0.5, 0.5]), make_observation([2.0, 2.0, 2.0])],
        labels=[False, True],
        version="demo-v1",
        dataset_hash="sha256:labeled-calibration",
        k=0.0,
    )

    assert profile.model_id == "qwen-model"
    assert profile.tokenizer_id == "qwen-tokenizer"
    assert profile.system_prompt_hash == "sha256:system"
    assert profile.signal == "entropy"
    assert profile.baseline.median == 1.0
    assert profile.baseline.mad_scale == pytest.approx(0.7413)
    assert profile.h > 0


def test_calibration_rejects_mixed_runtime_identities() -> None:
    first = make_observation([1.0, 2.0])
    second = make_observation([2.0, 3.0]).model_copy(
        update={"tokenizer_id": "other-tokenizer"}
    )

    with pytest.raises(ValueError, match="identity"):
        calibrate_entropy(
            [first, second],
            labels=[False, True],
            version="demo-v1",
            dataset_hash="sha256:labeled-calibration",
            k=0.0,
        )


def make_profile(*, k: float, h: float) -> CalibrationProfile:
    return CalibrationProfile(
        version=f"candidate-k{k}",
        model_id="qwen-model",
        tokenizer_id="qwen-tokenizer",
        system_prompt_hash="sha256:system",
        signal="entropy",
        baseline=RobustBaseline(median=1.0, mad_scale=0.7413),
        k=k,
        h=h,
        created_at="2026-08-25T00:00:00Z",
        dataset_hash="sha256:labeled-calibration",
    )


def test_development_selection_prefers_better_f1_without_test_input() -> None:
    selected = select_candidate_by_dev(
        [make_profile(k=0.0, h=2.0), make_profile(k=0.5, h=100.0)],
        [make_observation([0.5, 0.5]), make_observation([2.0, 2.0, 2.0])],
        labels=[False, True],
    )

    assert selected.k == 0.0
    assert selected.h == 2.0


def test_calibration_allows_only_numerical_system_entropy_drift() -> None:
    profile = calibrate_entropy(
        [
            make_observation([0.5, 0.5]),
            make_observation(
                [2.0, 2.0],
                system_entropies=(0.5000001, 1.0000001, 1.5000001),
            ),
        ],
        labels=[False, True],
        version="demo-v1",
        dataset_hash="sha256:labeled-calibration",
        k=0.0,
    )

    assert profile.baseline.median == 1.0

    with pytest.raises(ValueError, match="system entropy baselines"):
        calibrate_entropy(
            [
                make_observation([0.5, 0.5]),
                make_observation(
                    [2.0, 2.0],
                    system_entropies=(0.5, 1.0, 1.6),
                ),
            ],
            labels=[False, True],
            version="demo-v1",
            dataset_hash="sha256:labeled-calibration",
            k=0.0,
        )
