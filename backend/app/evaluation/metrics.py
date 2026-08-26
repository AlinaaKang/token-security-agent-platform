from __future__ import annotations

import math
from collections.abc import Sequence

from pydantic import BaseModel, Field


class BinaryMetrics(BaseModel, frozen=True):
    f1: float = Field(ge=0, le=1)
    auroc: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)


class LocalizationMetrics(BaseModel, frozen=True):
    onset_mae: float
    trigger_in_suffix_rate: float = Field(ge=0, le=1)


class LatencyMetrics(BaseModel, frozen=True):
    p50_ms: float = Field(ge=0)
    p95_ms: float = Field(ge=0)


def _auroc(labels: Sequence[bool], scores: Sequence[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("AUROC requires both positive and negative samples")

    ordered = sorted(zip(scores, labels, strict=True), key=lambda item: item[0])
    positive_rank_sum = 0.0
    start = 0
    while start < len(ordered):
        end = start + 1
        while end < len(ordered) and ordered[end][0] == ordered[start][0]:
            end += 1
        average_rank = ((start + 1) + end) / 2
        positive_rank_sum += average_rank * sum(label for _, label in ordered[start:end])
        start = end
    return (
        positive_rank_sum - positives * (positives + 1) / 2
    ) / (positives * negatives)


def binary_metrics(
    *, labels: Sequence[bool], scores: Sequence[float], threshold: float
) -> BinaryMetrics:
    if len(labels) != len(scores) or not labels:
        raise ValueError("labels and scores must have equal non-zero lengths")
    if not all(math.isfinite(score) for score in scores):
        raise ValueError("scores must be finite")

    predictions = [score >= threshold for score in scores]
    true_positive = sum(prediction and label for prediction, label in zip(predictions, labels))
    false_positive = sum(prediction and not label for prediction, label in zip(predictions, labels))
    false_negative = sum(not prediction and label for prediction, label in zip(predictions, labels))
    true_negative = sum(not prediction and not label for prediction, label in zip(predictions, labels))
    f1_denominator = 2 * true_positive + false_positive + false_negative
    f1 = 2 * true_positive / f1_denominator if f1_denominator else 0.0
    fpr_denominator = false_positive + true_negative
    false_positive_rate = false_positive / fpr_denominator if fpr_denominator else 0.0
    return BinaryMetrics(
        f1=f1,
        auroc=_auroc(labels, scores),
        false_positive_rate=false_positive_rate,
    )


def localization_metrics(
    *,
    suffix_starts: Sequence[int],
    suffix_ends: Sequence[int],
    predicted_onsets: Sequence[int | None],
) -> LocalizationMetrics:
    if not (
        len(suffix_starts) == len(suffix_ends) == len(predicted_onsets)
    ) or not suffix_starts:
        raise ValueError("localization inputs must have equal non-zero lengths")

    detected_errors = [
        abs(prediction - start)
        for start, prediction in zip(suffix_starts, predicted_onsets, strict=True)
        if prediction is not None
    ]
    onset_mae = (
        sum(detected_errors) / len(detected_errors)
        if detected_errors
        else float("nan")
    )
    hits = sum(
        prediction is not None and start <= prediction < end
        for start, end, prediction in zip(
            suffix_starts, suffix_ends, predicted_onsets, strict=True
        )
    )
    return LocalizationMetrics(
        onset_mae=onset_mae,
        trigger_in_suffix_rate=hits / len(suffix_starts),
    )


def _percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + fraction * (ordered[upper] - ordered[lower])


def latency_metrics(latencies_ms: Sequence[float]) -> LatencyMetrics:
    if not latencies_ms:
        raise ValueError("latencies must not be empty")
    if not all(math.isfinite(value) and value >= 0 for value in latencies_ms):
        raise ValueError("latencies must be finite and non-negative")
    return LatencyMetrics(
        p50_ms=_percentile(latencies_ms, 0.5),
        p95_ms=_percentile(latencies_ms, 0.95),
    )
