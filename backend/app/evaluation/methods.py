from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, Field

from app.detection.baselines import global_nll_score, windowed_nll_score
from app.detection.calibrator import (
    select_f1_threshold,
    select_threshold_at_max_fpr,
)
from app.evaluation.metrics import binary_metrics
from app.model.runtime import ModelObservation


WINDOW_SIZE_CANDIDATES = (8, 16, 32)


class MethodProfile(BaseModel, frozen=True):
    method_id: Literal["global_nll", "window_nll"]
    threshold: float = Field(gt=0, allow_inf_nan=False)
    low_fpr_threshold: float = Field(gt=0, allow_inf_nan=False)
    window_size: int | None = Field(default=None, gt=0)


def _identity(observation: ModelObservation) -> tuple[str, str, str]:
    return (
        observation.model_id,
        observation.tokenizer_id,
        observation.system_prompt_hash,
    )


def _validate_observations(
    calibration_observations: Sequence[ModelObservation],
    calibration_labels: Sequence[bool],
    development_observations: Sequence[ModelObservation],
    development_labels: Sequence[bool],
) -> None:
    if not calibration_observations or len(calibration_observations) != len(
        calibration_labels
    ):
        raise ValueError(
            "calibration observations and labels must have equal non-zero lengths"
        )
    if not development_observations or len(development_observations) != len(
        development_labels
    ):
        raise ValueError(
            "development observations and labels must have equal non-zero lengths"
        )
    expected_identity = _identity(calibration_observations[0])
    if any(
        _identity(observation) != expected_identity
        for observation in (
            *calibration_observations[1:],
            *development_observations,
        )
    ):
        raise ValueError("NLL observations have mixed runtime identity")


def _nll(observation: ModelObservation) -> list[float]:
    return [token.nll for token in observation.user_tokens]


def fit_global_nll(
    *,
    calibration_observations: Sequence[ModelObservation],
    calibration_labels: Sequence[bool],
    development_observations: Sequence[ModelObservation],
    development_labels: Sequence[bool],
) -> MethodProfile:
    _validate_observations(
        calibration_observations,
        calibration_labels,
        development_observations,
        development_labels,
    )
    calibration_scores = [
        global_nll_score(_nll(observation))
        for observation in calibration_observations
    ]
    development_scores = [
        global_nll_score(_nll(observation))
        for observation in development_observations
    ]
    return MethodProfile(
        method_id="global_nll",
        threshold=select_f1_threshold(calibration_labels, calibration_scores),
        low_fpr_threshold=select_threshold_at_max_fpr(
            development_labels,
            development_scores,
            max_fpr=0.10,
        ),
    )


def fit_window_nll(
    *,
    calibration_observations: Sequence[ModelObservation],
    calibration_labels: Sequence[bool],
    development_observations: Sequence[ModelObservation],
    development_labels: Sequence[bool],
) -> MethodProfile:
    _validate_observations(
        calibration_observations,
        calibration_labels,
        development_observations,
        development_labels,
    )
    candidates: list[tuple[float, float, int, float]] = []
    for window_size in WINDOW_SIZE_CANDIDATES:
        calibration_scores = [
            windowed_nll_score(_nll(observation), window_size=window_size)
            for observation in calibration_observations
        ]
        threshold = select_f1_threshold(calibration_labels, calibration_scores)
        development_scores = [
            windowed_nll_score(_nll(observation), window_size=window_size)
            for observation in development_observations
        ]
        metrics = binary_metrics(
            labels=development_labels,
            scores=development_scores,
            threshold=threshold,
        )
        candidates.append(
            (
                metrics.f1,
                -metrics.false_positive_rate,
                window_size,
                threshold,
            )
        )

    _, _, selected_window, selected_threshold = max(candidates)
    selected_development_scores = [
        windowed_nll_score(_nll(observation), window_size=selected_window)
        for observation in development_observations
    ]
    return MethodProfile(
        method_id="window_nll",
        threshold=selected_threshold,
        low_fpr_threshold=select_threshold_at_max_fpr(
            development_labels,
            selected_development_scores,
            max_fpr=0.10,
        ),
        window_size=selected_window,
    )


def score_method(profile: MethodProfile, observation: ModelObservation) -> float:
    sequence = _nll(observation)
    if profile.method_id == "global_nll":
        return global_nll_score(sequence)
    if profile.window_size is None:
        raise ValueError("window_nll profile requires window_size")
    return windowed_nll_score(sequence, window_size=profile.window_size)
