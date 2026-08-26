from __future__ import annotations

import math
from collections.abc import Sequence


def _validate_nll(nll: Sequence[float]) -> None:
    if not nll:
        raise ValueError("NLL sequence must not be empty")
    if not all(math.isfinite(value) and value >= 0 for value in nll):
        raise ValueError("NLL values must be finite and non-negative")


def global_nll_score(nll: Sequence[float]) -> float:
    _validate_nll(nll)
    return sum(nll) / len(nll)


def global_perplexity_score(nll: Sequence[float]) -> float:
    return math.exp(global_nll_score(nll))


def windowed_nll_score(nll: Sequence[float], *, window_size: int) -> float:
    _validate_nll(nll)
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    effective_size = min(window_size, len(nll))
    rolling_sum = sum(nll[:effective_size])
    maximum_mean = rolling_sum / effective_size
    for end in range(effective_size, len(nll)):
        rolling_sum += nll[end] - nll[end - effective_size]
        maximum_mean = max(maximum_mean, rolling_sum / effective_size)
    return maximum_mean
