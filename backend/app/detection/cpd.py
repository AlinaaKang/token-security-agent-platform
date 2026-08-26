from __future__ import annotations

import math
import statistics
from collections.abc import Sequence

from pydantic import BaseModel, Field


MAD_SCALE = 1.4826
MAD_FLOOR = 1e-6


class RobustBaseline(BaseModel, frozen=True):
    median: float
    mad_scale: float = Field(gt=0)


class CPDTrace(BaseModel, frozen=True):
    score: float = Field(ge=0)
    alarm_index: int | None = Field(default=None, ge=0)
    onset_index: int | None = Field(default=None, ge=0)
    alarm_indices: tuple[int, ...]
    z_scores: tuple[float, ...]
    cumulative: tuple[float, ...]


def fit_system_baseline(values: Sequence[float]) -> RobustBaseline:
    if not values:
        raise ValueError("baseline values must not be empty")
    if not all(math.isfinite(value) for value in values):
        raise ValueError("baseline values must be finite")
    median = float(statistics.median(values))
    absolute_deviations = [abs(value - median) for value in values]
    mad_scale = MAD_SCALE * float(statistics.median(absolute_deviations))
    return RobustBaseline(median=median, mad_scale=max(mad_scale, MAD_FLOOR))


def run_cpd(
    values: Sequence[float],
    baseline: RobustBaseline,
    *,
    k: float,
    h: float,
    reset_after_alarm: bool = False,
) -> CPDTrace:
    if k < 0:
        raise ValueError("k must be non-negative")
    if h <= 0:
        raise ValueError("h must be positive")
    if not all(math.isfinite(value) for value in values):
        raise ValueError("CPD values must be finite")

    cumulative_value = 0.0
    segment_start: int | None = None
    first_onset: int | None = None
    alarm_indices: list[int] = []
    z_scores: list[float] = []
    cumulative: list[float] = []
    maximum = 0.0

    for index, value in enumerate(values):
        z_score = (value - baseline.median) / max(baseline.mad_scale, MAD_FLOOR)
        previous = cumulative_value
        cumulative_value = max(0.0, cumulative_value + z_score - k)
        if previous == 0.0 and cumulative_value > 0.0:
            segment_start = index
        if cumulative_value == 0.0:
            segment_start = None
        maximum = max(maximum, cumulative_value)

        if cumulative_value >= h:
            alarm_indices.append(index)
            if first_onset is None:
                first_onset = segment_start
            if reset_after_alarm:
                cumulative_value = 0.0
                segment_start = None

        z_scores.append(z_score)
        cumulative.append(cumulative_value)

    return CPDTrace(
        score=maximum,
        alarm_index=alarm_indices[0] if alarm_indices else None,
        onset_index=first_onset,
        alarm_indices=tuple(alarm_indices),
        z_scores=tuple(z_scores),
        cumulative=tuple(cumulative),
    )
