from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.evaluation.ablation import (
    AblationMethod,
    AblationObservation,
    AblationProfile,
    EvaluationDomain,
    OperatingPoint,
    evaluate_ablation,
    select_ablation_profiles,
)


HASH = "sha256:" + "a" * 64


def _row(
    sample_id: str,
    *,
    split: str = "dev",
    domain: EvaluationDomain = EvaluationDomain.BENIGN_PLAIN,
    label_risky: bool = False,
    severity: str = "safe",
    score: float = 0.1,
    production_alarm: bool = False,
    family: str | None = None,
    onset: int | None = None,
    suffix_start: int | None = None,
    suffix_end: int | None = None,
    semantic_latency_ms: float = 2.0,
    total_latency_ms: float = 10.0,
) -> AblationObservation:
    return AblationObservation.model_validate(
        {
            "sample_id": sample_id,
            "group_id": f"group-{sample_id}",
            "split": split,
            "domain": domain,
            "label_risky": label_risky,
            "attack_family": family,
            "semantic_severity": severity,
            "semantic_verification": "performed",
            "detector_score": score,
            "production_cpd_alarm": production_alarm,
            "predicted_onset": onset,
            "suffix_start": suffix_start,
            "suffix_end": suffix_end,
            "semantic_latency_ms": semantic_latency_ms,
            "total_latency_ms": total_latency_ms,
        }
    )


def _find(
    profiles: tuple[AblationProfile, ...],
    method: AblationMethod,
    operating_point: OperatingPoint,
) -> AblationProfile:
    return next(
        profile
        for profile in profiles
        if profile.method is method and profile.operating_point is operating_point
    )


def test_observation_rejects_prompt_and_inconsistent_domain_labels() -> None:
    payload = _row("safe").model_dump(mode="json")
    payload["prompt"] = "SAFE_PRIVATE_PROMPT"
    with pytest.raises(ValidationError):
        AblationObservation.model_validate(payload)

    with pytest.raises(ValidationError, match="benign domains require"):
        _row("bad-label", label_risky=True)

    with pytest.raises(ValidationError, match="optimized suffix observations require"):
        _row(
            "bad-suffix",
            domain=EvaluationDomain.OPTIMIZED_SUFFIX,
            label_risky=True,
            family="gcg",
        )


def test_profile_selection_uses_dev_only_and_selects_highest_recall_under_fpr() -> None:
    rows = (
        _row("b1", score=0.1),
        _row("b2", score=0.2),
        _row("p1", domain=EvaluationDomain.SEMANTIC_UNSAFE, label_risky=True,
             severity="unsafe", score=0.8),
        _row("p2", domain=EvaluationDomain.SEMANTIC_UNSAFE, label_risky=True,
             severity="safe", score=0.7),
    )

    profiles = select_ablation_profiles(rows, dataset_hash=HASH)

    cpd = _find(profiles, AblationMethod.CPD_ONLY, OperatingPoint.FPR_10)
    assert cpd.constraint_satisfied is True
    assert cpd.detector_threshold == pytest.approx(0.7)
    assert cpd.dev_recall == 1.0
    assert cpd.dev_false_positive_rate == 0.0
    assert len(profiles) == 9

    with pytest.raises(ValueError, match="dev observations only"):
        select_ablation_profiles(
            (_row("test-row", split="test"),), dataset_hash=HASH
        )


def test_semantic_and_fusion_profiles_mark_impossible_fpr_constraint() -> None:
    rows = (
        _row("b1", severity="unsafe", score=0.1),
        _row("b2", severity="controversial", score=0.2),
        _row("p1", domain=EvaluationDomain.SEMANTIC_UNSAFE, label_risky=True,
             severity="unsafe", score=0.8),
    )

    profiles = select_ablation_profiles(rows, dataset_hash=HASH)

    semantic = _find(
        profiles, AblationMethod.SEMANTIC_ONLY, OperatingPoint.FPR_05
    )
    fusion = _find(profiles, AblationMethod.FUSION, OperatingPoint.FPR_05)
    assert semantic.constraint_satisfied is False
    assert semantic.semantic_policy == "unsafe_only"
    assert semantic.dev_false_positive_rate == 0.5
    assert fusion.constraint_satisfied is False
    assert fusion.dev_false_positive_rate == 1.0


def test_profile_selection_is_deterministic_for_ties() -> None:
    rows = (
        _row("b1", score=0.1),
        _row("p1", domain=EvaluationDomain.SEMANTIC_UNSAFE, label_risky=True,
             severity="unsafe", score=0.8),
    )
    first = select_ablation_profiles(rows, dataset_hash=HASH)
    second = select_ablation_profiles(tuple(reversed(rows)), dataset_hash=HASH)
    assert first == second


def _test_rows() -> tuple[AblationObservation, ...]:
    return (
        _row("plain", split="test", score=0.1),
        _row(
            "shift",
            split="test",
            domain=EvaluationDomain.BENIGN_SHIFT,
            score=0.9,
            production_alarm=True,
        ),
        _row("hard-negative", split="test", severity="controversial", score=0.2),
        _row(
            "semantic-risk",
            split="test",
            domain=EvaluationDomain.SEMANTIC_UNSAFE,
            label_risky=True,
            severity="unsafe",
            score=0.1,
        ),
        _row(
            "gcg-risk",
            split="test",
            domain=EvaluationDomain.OPTIMIZED_SUFFIX,
            label_risky=True,
            score=0.8,
            production_alarm=True,
            family="GCG",
            onset=12,
            suffix_start=10,
            suffix_end=20,
        ),
        _row(
            "autodan-risk",
            split="test",
            domain=EvaluationDomain.OPTIMIZED_SUFFIX,
            label_risky=True,
            severity="controversial",
            score=0.7,
            production_alarm=True,
            family="AutoDAN",
            suffix_start=15,
            suffix_end=25,
        ),
    )


def test_evaluation_reports_hand_checked_metrics_and_no_sample_data() -> None:
    dev_rows = tuple(
        row.model_copy(update={"split": "dev"}) for row in _test_rows()
    )
    profiles = select_ablation_profiles(dev_rows, dataset_hash=HASH)

    report = evaluate_ablation(
        _test_rows(),
        profiles,
        benchmark_version="agent-ablation-v1",
        dataset_hash=HASH,
        source_coverage={
            "autodan": "verified",
            "beast": "source_unavailable",
            "gcg": "verified",
        },
    )

    semantic = report.result(AblationMethod.SEMANTIC_ONLY, OperatingPoint.PRODUCTION)
    cpd = report.result(AblationMethod.CPD_ONLY, OperatingPoint.PRODUCTION)
    fusion = report.result(AblationMethod.FUSION, OperatingPoint.PRODUCTION)

    assert semantic.metrics.model_dump() == {
        "true_positive": 2,
        "false_positive": 1,
        "true_negative": 2,
        "false_negative": 1,
        "precision": pytest.approx(2 / 3),
        "recall": pytest.approx(2 / 3),
        "f1": pytest.approx(2 / 3),
        "false_positive_rate": pytest.approx(1 / 3),
    }
    assert cpd.metrics.true_positive == 2
    assert cpd.metrics.false_positive == 1
    assert fusion.metrics.true_positive == 3
    assert fusion.metrics.false_positive == 2
    assert fusion.metrics.recall == 1.0
    assert fusion.metrics.f1 == pytest.approx(0.75)
    assert fusion.action_counts.model_dump() == {
        "allow": 1,
        "review": 2,
        "block": 3,
    }
    assert cpd.family_metrics["gcg"].recall == 1.0
    assert cpd.domain_metrics[EvaluationDomain.BENIGN_SHIFT].false_positive_rate == 1.0
    assert cpd.localization is not None
    assert cpd.localization.eligible_count == 2
    assert cpd.localization.predicted_count == 1
    assert cpd.localization.onset_mae == 2.0
    assert cpd.localization.trigger_in_suffix_rate == 0.5
    assert report.coverage_gaps == ("beast",)
    assert report.requested_count == 6
    assert report.completed_count == 6
    assert report.failed_count == 0

    payload = report.model_dump_json()
    parsed = json.loads(payload)
    assert "sample_id" not in payload
    assert "group-" not in payload
    assert "SAFE_PRIVATE_PROMPT" not in payload
    assert "methods" in parsed


def test_evaluation_rejects_wrong_split_duplicate_ids_and_profile_hash() -> None:
    rows = _test_rows()
    profiles = select_ablation_profiles(
        tuple(row.model_copy(update={"split": "dev"}) for row in rows),
        dataset_hash=HASH,
    )
    with pytest.raises(ValueError, match="test observations only"):
        evaluate_ablation(
            (rows[0].model_copy(update={"split": "dev"}),), profiles,
            benchmark_version="agent-ablation-v1", dataset_hash=HASH,
            source_coverage={},
        )
    with pytest.raises(ValueError, match="duplicate sample IDs"):
        evaluate_ablation(
            (rows[0], rows[0]), profiles,
            benchmark_version="agent-ablation-v1", dataset_hash=HASH,
            source_coverage={},
        )
    bad_profiles = tuple(
        profile.model_copy(update={"dataset_hash": "sha256:" + "b" * 64})
        for profile in profiles
    )
    with pytest.raises(ValueError, match="profile dataset hash mismatch"):
        evaluate_ablation(
            rows, bad_profiles,
            benchmark_version="agent-ablation-v1", dataset_hash=HASH,
            source_coverage={},
        )
