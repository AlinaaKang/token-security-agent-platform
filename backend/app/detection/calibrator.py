from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import UTC, datetime

from app.detection.calibration import CalibrationProfile
from app.detection.cpd import fit_system_baseline, run_cpd
from app.evaluation.metrics import binary_metrics
from app.model.runtime import ModelObservation


SYSTEM_ENTROPY_ABS_TOLERANCE = 1e-4


def _validate_labeled_scores(
    labels: Sequence[bool], scores: Sequence[float]
) -> None:
    if not labels or len(labels) != len(scores):
        raise ValueError("labels and scores must have equal non-zero lengths")
    if not any(labels) or all(labels):
        raise ValueError("labels must contain both classes")
    if not all(math.isfinite(score) and score >= 0 for score in scores):
        raise ValueError("scores must be finite and non-negative")


def _threshold_metrics(
    labels: Sequence[bool], scores: Sequence[float], threshold: float
) -> tuple[float, float, float]:
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
    true_negative = len(labels) - true_positive - false_positive - false_negative
    f1_denominator = 2 * true_positive + false_positive + false_negative
    f1 = 2 * true_positive / f1_denominator if f1_denominator else 0.0
    recall_denominator = true_positive + false_negative
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    fpr_denominator = false_positive + true_negative
    fpr = false_positive / fpr_denominator if fpr_denominator else 0.0
    return f1, recall, fpr


def _candidate_thresholds(scores: Sequence[float]) -> tuple[float, ...]:
    positive_scores = {score for score in scores if score > 0}
    maximum = max(scores)
    above_maximum = math.nextafter(maximum, math.inf)
    return tuple(sorted(positive_scores | {above_maximum}))


def select_f1_threshold(
    labels: Sequence[bool], scores: Sequence[float]
) -> float:
    _validate_labeled_scores(labels, scores)
    return max(
        _candidate_thresholds(scores),
        key=lambda threshold: (
            _threshold_metrics(labels, scores, threshold)[0],
            -_threshold_metrics(labels, scores, threshold)[2],
            threshold,
        ),
    )


def select_threshold_at_max_fpr(
    labels: Sequence[bool],
    scores: Sequence[float],
    *,
    max_fpr: float,
) -> float:
    _validate_labeled_scores(labels, scores)
    if not 0 <= max_fpr <= 1:
        raise ValueError("max_fpr must be between 0 and 1")
    feasible = [
        threshold
        for threshold in _candidate_thresholds(scores)
        if _threshold_metrics(labels, scores, threshold)[2] <= max_fpr
    ]
    return max(
        feasible,
        key=lambda threshold: (
            _threshold_metrics(labels, scores, threshold)[1],
            _threshold_metrics(labels, scores, threshold)[0],
            threshold,
        ),
    )


def calibrate_entropy(
    observations: Sequence[ModelObservation],
    labels: Sequence[bool],
    *,
    version: str,
    dataset_hash: str,
    k: float,
) -> CalibrationProfile:
    if not observations:
        raise ValueError("calibration observations must not be empty")
    if len(observations) != len(labels):
        raise ValueError("observations and labels must have equal lengths")

    first = observations[0]
    identity = (
        first.model_id,
        first.tokenizer_id,
        first.system_prompt_hash,
    )
    if any(
        (item.model_id, item.tokenizer_id, item.system_prompt_hash) != identity
        for item in observations[1:]
    ):
        raise ValueError("calibration observations have mixed runtime identity")
    for item in observations[1:]:
        if len(item.system_entropies) != len(first.system_entropies):
            raise ValueError(
                "calibration observations have mixed system entropy baselines: "
                "token count differs"
            )
        maximum_drift = max(
            abs(current - reference)
            for current, reference in zip(
                item.system_entropies,
                first.system_entropies,
                strict=True,
            )
        )
        if maximum_drift > SYSTEM_ENTROPY_ABS_TOLERANCE:
            raise ValueError(
                "calibration observations have mixed system entropy baselines: "
                f"max_abs_drift={maximum_drift:.8g}"
            )

    sequences = [
        [token.entropy for token in observation.user_tokens]
        for observation in observations
    ]
    baseline = fit_system_baseline(first.system_entropies)
    scores = [
        run_cpd(sequence, baseline, k=k, h=math.inf).score
        for sequence in sequences
    ]
    threshold = select_f1_threshold(labels, scores)

    return CalibrationProfile(
        version=version,
        model_id=first.model_id,
        tokenizer_id=first.tokenizer_id,
        system_prompt_hash=first.system_prompt_hash,
        signal="entropy",
        baseline=baseline,
        k=k,
        h=threshold,
        created_at=datetime.now(UTC),
        dataset_hash=dataset_hash,
    )


def select_candidate_by_dev(
    candidates: Sequence[CalibrationProfile],
    observations: Sequence[ModelObservation],
    labels: Sequence[bool],
) -> CalibrationProfile:
    if not candidates:
        raise ValueError("calibration candidates must not be empty")
    if not observations or len(observations) != len(labels):
        raise ValueError("development observations and labels must have equal lengths")
    _validate_labeled_scores(labels, [0.0] * len(labels))

    ranked: list[tuple[float, float, float, CalibrationProfile]] = []
    for candidate in candidates:
        scores: list[float] = []
        for observation in observations:
            candidate.ensure_compatible(
                model_id=observation.model_id,
                tokenizer_id=observation.tokenizer_id,
                system_prompt_hash=observation.system_prompt_hash,
            )
            scores.append(
                run_cpd(
                    [token.entropy for token in observation.user_tokens],
                    candidate.baseline,
                    k=candidate.k,
                    h=math.inf,
                ).score
            )
        metrics = binary_metrics(
            labels=labels,
            scores=scores,
            threshold=candidate.h,
        )
        ranked.append(
            (
                metrics.f1,
                -metrics.false_positive_rate,
                -candidate.k,
                candidate,
            )
        )

    return max(ranked, key=lambda item: item[:3])[3]
