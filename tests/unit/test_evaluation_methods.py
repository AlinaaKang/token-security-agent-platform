from __future__ import annotations

import inspect

import pytest

from app.evaluation.methods import (
    fit_global_nll,
    fit_window_nll,
    score_method,
)
from app.model.runtime import ModelObservation
from app.model.token_stats import ObservedUserToken


def make_observation(nll: list[float], *, model_id: str = "qwen-model") -> ModelObservation:
    return ModelObservation(
        model_id=model_id,
        tokenizer_id="qwen-tokenizer",
        system_prompt_hash="sha256:system",
        system_entropies=(0.5, 1.0, 1.5),
        user_tokens=tuple(
            ObservedUserToken(
                user_index=index,
                full_index=index + 1,
                token_id=index + 10,
                token_text=f"safe-{index}",
                char_start=index,
                char_end=index + 1,
                entropy=1.0,
                nll=value,
            )
            for index, value in enumerate(nll)
        ),
        latency_ms=1.0,
    )


def test_global_nll_fits_threshold_without_test_input() -> None:
    profile = fit_global_nll(
        calibration_observations=[
            make_observation([1.0, 1.0]),
            make_observation([2.0, 2.0]),
            make_observation([5.0, 5.0]),
            make_observation([6.0, 6.0]),
        ],
        calibration_labels=[False, False, True, True],
        development_observations=[
            make_observation([1.5, 1.5]),
            make_observation([5.5, 5.5]),
        ],
        development_labels=[False, True],
    )

    assert profile.method_id == "global_nll"
    assert profile.threshold == pytest.approx(5.0)
    assert profile.window_size is None
    assert score_method(profile, make_observation([2.0, 4.0])) == pytest.approx(3.0)
    assert "test" not in inspect.signature(fit_global_nll).parameters


def test_window_nll_selects_only_declared_windows_with_deterministic_tie_break() -> None:
    calibration = [
        make_observation([1.0] * 40),
        make_observation([2.0] * 40),
        make_observation([5.0] * 40),
        make_observation([6.0] * 40),
    ]
    development = [make_observation([1.5] * 40), make_observation([5.5] * 40)]

    profile = fit_window_nll(
        calibration_observations=calibration,
        calibration_labels=[False, False, True, True],
        development_observations=development,
        development_labels=[False, True],
    )

    assert profile.method_id == "window_nll"
    assert profile.window_size == 32
    assert profile.threshold == pytest.approx(5.0)
    assert "test" not in inspect.signature(fit_window_nll).parameters


def test_nll_fit_rejects_mixed_runtime_identity() -> None:
    with pytest.raises(ValueError, match="runtime identity"):
        fit_global_nll(
            calibration_observations=[
                make_observation([1.0]),
                make_observation([5.0], model_id="other-model"),
            ],
            calibration_labels=[False, True],
            development_observations=[
                make_observation([1.0]),
                make_observation([5.0]),
            ],
            development_labels=[False, True],
        )
