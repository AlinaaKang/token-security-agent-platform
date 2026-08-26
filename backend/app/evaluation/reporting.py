from __future__ import annotations

import math
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from app.evaluation.metrics import binary_metrics, latency_metrics, localization_metrics
from app.evaluation.normalize import PromptRecord


class PromptPrediction(BaseModel, frozen=True):
    sample_id: str = Field(min_length=1)
    score: float = Field(ge=0)
    alarm_index: int | None = Field(default=None, ge=0)
    onset_char_start: int | None = Field(default=None, ge=0)
    latency_ms: float = Field(ge=0)


@dataclass(frozen=True)
class MethodReportInput:
    display_name: str
    predictions: Sequence[PromptPrediction]
    threshold: float
    low_fpr_threshold: float
    profile: Mapping[str, str | int | float | None]
    include_localization: bool = False


def _operating_point(
    labels: Sequence[bool], scores: Sequence[float], threshold: float
) -> dict[str, float]:
    metrics = binary_metrics(labels=labels, scores=scores, threshold=threshold)
    predictions = [score >= threshold for score in scores]
    true_positive = sum(
        prediction and label
        for prediction, label in zip(predictions, labels, strict=True)
    )
    false_positive = sum(
        prediction and not label
        for prediction, label in zip(predictions, labels, strict=True)
    )
    false_negative = sum(
        not prediction and label
        for prediction, label in zip(predictions, labels, strict=True)
    )
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    return {
        "threshold": threshold,
        "precision": (
            true_positive / precision_denominator if precision_denominator else 0.0
        ),
        "recall": true_positive / recall_denominator if recall_denominator else 0.0,
        "f1": metrics.f1,
        "auroc": metrics.auroc,
        "false_positive_rate": metrics.false_positive_rate,
    }


def _family_operating_point(
    scores: Sequence[float], threshold: float
) -> dict[str, float | int]:
    detected = sum(score >= threshold for score in scores)
    return {
        "detected": detected,
        "missed": len(scores) - detected,
        "recall": detected / len(scores),
    }


def _method_report(
    *,
    records: Sequence[PromptRecord],
    method: MethodReportInput,
) -> dict[str, Any]:
    if not method.display_name.strip():
        raise ValueError("method display_name must not be blank")
    if not math.isfinite(method.threshold) or method.threshold <= 0:
        raise ValueError("threshold must be finite and positive")
    if (
        not math.isfinite(method.low_fpr_threshold)
        or method.low_fpr_threshold <= 0
    ):
        raise ValueError("low_fpr_threshold must be finite and positive")

    record_ids = [record.sample_id for record in records]
    prediction_ids = [prediction.sample_id for prediction in method.predictions]
    if len(set(record_ids)) != len(record_ids) or len(set(prediction_ids)) != len(
        prediction_ids
    ):
        raise ValueError("benchmark sample IDs must be unique")
    if set(record_ids) != set(prediction_ids):
        raise ValueError("record and prediction sample IDs must match exactly")

    prediction_by_id = {
        prediction.sample_id: prediction for prediction in method.predictions
    }
    ordered_predictions = [prediction_by_id[sample_id] for sample_id in record_ids]
    labels = [record.label_suffix_attack for record in records]
    scores = [prediction.score for prediction in ordered_predictions]

    families: dict[str, dict[str, Any]] = {}
    evaluated_families = sorted(
        {
            record.attack_family.casefold()
            for record in records
            if record.label_suffix_attack and record.attack_family is not None
        }
    )
    for family in evaluated_families:
        family_rows = [
            (record, prediction_by_id[record.sample_id])
            for record in records
            if record.attack_family is not None
            and record.attack_family.casefold() == family
        ]
        family_scores = sorted(prediction.score for _, prediction in family_rows)
        f1_selected = _family_operating_point(family_scores, method.threshold)
        families[family] = {
            "count": len(family_rows),
            "operating_points": {
                "f1_selected": f1_selected,
                "low_fpr_selected_on_dev": _family_operating_point(
                    family_scores, method.low_fpr_threshold
                ),
            },
            "score": {
                "min": family_scores[0],
                "median": statistics.median(family_scores),
                "max": family_scores[-1],
            },
        }

    localization: dict[str, Any] | None = None
    if method.include_localization:
        attack_rows = [
            (record, prediction_by_id[record.sample_id])
            for record in records
            if record.label_suffix_attack
        ]
        suffix_starts = [
            record.suffix_char_start
            for record, _ in attack_rows
            if record.suffix_char_start is not None
        ]
        suffix_ends = [
            len(record.prompt)
            for record, _ in attack_rows
            if record.suffix_char_start is not None
        ]
        predicted_onsets = [
            prediction.onset_char_start
            for record, prediction in attack_rows
            if record.suffix_char_start is not None
        ]
        localization = localization_metrics(
            suffix_starts=suffix_starts,
            suffix_ends=suffix_ends,
            predicted_onsets=predicted_onsets,
        ).model_dump(mode="json")
    latency = latency_metrics(
        [prediction.latency_ms for prediction in ordered_predictions]
    )

    return {
        "display_name": method.display_name,
        "profile": dict(method.profile),
        "operating_points": {
            "f1_selected": _operating_point(labels, scores, method.threshold),
            "low_fpr_selected_on_dev": _operating_point(
                labels, scores, method.low_fpr_threshold
            ),
        },
        "families": families,
        "localization": localization,
        "latency_ms": latency.model_dump(mode="json"),
    }


def build_benchmark_report(
    *,
    records: Sequence[PromptRecord],
    methods: Mapping[str, MethodReportInput],
    provenance: Mapping[str, Any],
    expected_families: Sequence[str],
) -> dict[str, Any]:
    if not records:
        raise ValueError("benchmark records must not be empty")
    expected_methods = {"global_nll", "window_nll", "entropy_cpd"}
    if set(methods) != expected_methods:
        raise ValueError("benchmark requires exactly three methods")

    record_ids = [record.sample_id for record in records]
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("benchmark sample IDs must be unique")
    labels = [record.label_suffix_attack for record in records]
    evaluated_families = sorted(
        {
            record.attack_family.casefold()
            for record in records
            if record.label_suffix_attack and record.attack_family is not None
        }
    )

    normalized_expected = sorted({family.casefold() for family in expected_families})
    return {
        "schema_version": 2,
        "counts": {
            "total": len(records),
            "attacks": sum(labels),
            "benign": len(records) - sum(labels),
        },
        "methods": {
            method_id: _method_report(records=records, method=methods[method_id])
            for method_id in ("global_nll", "window_nll", "entropy_cpd")
        },
        "not_evaluated": [
            family
            for family in normalized_expected
            if family not in evaluated_families
        ],
        "provenance": dict(provenance),
    }
