from __future__ import annotations

import json

import pytest

from app.evaluation.normalize import PromptRecord
from app.evaluation.reporting import (
    MethodReportInput,
    PromptPrediction,
    build_benchmark_report,
)


def make_record(
    *,
    sample_id: str,
    prompt: str,
    attack_family: str | None = None,
    suffix: str | None = None,
) -> PromptRecord:
    is_attack = attack_family is not None
    suffix_start = len(prompt) - len(suffix or "") if is_attack else None
    return PromptRecord(
        sample_id=sample_id,
        prompt=prompt,
        label_suffix_attack=is_attack,
        attack_family=attack_family,
        suffix_text=suffix,
        suffix_char_start=suffix_start,
        source_dataset="synthetic-safe",
        group_id=f"group-{sample_id}",
    )


def test_benchmark_report_is_aggregate_and_prompt_free() -> None:
    records = [
        make_record(sample_id="benign-1", prompt="SAFE_BENIGN_TEXT"),
        make_record(
            sample_id="gcg-1",
            prompt="SAFE_GCG_BASE_GCG_SUFFIX",
            attack_family="gcg",
            suffix="_GCG_SUFFIX",
        ),
        make_record(
            sample_id="autodan-1",
            prompt="SAFE_AUTODAN_BASE_AUTODAN_SUFFIX",
            attack_family="AutoDAN",
            suffix="_AUTODAN_SUFFIX",
        ),
    ]
    predictions = [
        PromptPrediction(sample_id="benign-1", score=0.1, latency_ms=1.0),
        PromptPrediction(
            sample_id="gcg-1",
            score=0.9,
            alarm_index=8,
            onset_char_start=len("SAFE_GCG_BASE"),
            latency_ms=2.0,
        ),
        PromptPrediction(sample_id="autodan-1", score=0.6, latency_ms=3.0),
    ]

    report = build_benchmark_report(
        records=records,
        methods={
            "global_nll": MethodReportInput(
                display_name="Global NLL",
                predictions=predictions,
                threshold=0.5,
                low_fpr_threshold=0.8,
                profile={"threshold": 0.5},
            ),
            "window_nll": MethodReportInput(
                display_name="Window NLL",
                predictions=predictions,
                threshold=0.5,
                low_fpr_threshold=0.8,
                profile={"threshold": 0.5, "window_size": 16},
            ),
            "entropy_cpd": MethodReportInput(
                display_name="Entropy-CPD",
                predictions=predictions,
                threshold=0.5,
                low_fpr_threshold=0.8,
                profile={"threshold": 0.5, "k": 0.0},
                include_localization=True,
            ),
        },
        provenance={"calibration_version": "paper-compatible-v1"},
        expected_families=("gcg", "autodan", "beast"),
    )

    assert report["schema_version"] == 2
    assert set(report["methods"]) == {
        "global_nll",
        "window_nll",
        "entropy_cpd",
    }
    cpd = report["methods"]["entropy_cpd"]
    assert cpd["operating_points"]["f1_selected"]["f1"] == 1.0
    assert cpd["operating_points"]["f1_selected"]["false_positive_rate"] == 0.0
    assert cpd["families"]["gcg"]["operating_points"]["f1_selected"]["recall"] == 1.0
    assert cpd["families"]["autodan"]["operating_points"] == {
        "f1_selected": {"detected": 1, "missed": 0, "recall": 1.0},
        "low_fpr_selected_on_dev": {
            "detected": 0,
            "missed": 1,
            "recall": 0.0,
        },
    }
    assert cpd["families"]["gcg"]["operating_points"] == {
        "f1_selected": {"detected": 1, "missed": 0, "recall": 1.0},
        "low_fpr_selected_on_dev": {
            "detected": 1,
            "missed": 0,
            "recall": 1.0,
        },
    }
    assert "low_fpr_selected_on_dev" in cpd["operating_points"]
    assert cpd["localization"]["trigger_in_suffix_rate"] == pytest.approx(0.5)
    assert report["methods"]["global_nll"]["localization"] is None
    assert report["methods"]["window_nll"]["localization"] is None
    assert report["not_evaluated"] == ["beast"]

    serialized = json.dumps(report, ensure_ascii=False)
    for record in records:
        assert record.prompt not in serialized
        if record.suffix_text:
            assert record.suffix_text not in serialized


def test_benchmark_report_requires_exact_prediction_identity() -> None:
    records = [make_record(sample_id="benign-1", prompt="SAFE_BENIGN_TEXT")]
    predictions = [
        PromptPrediction(sample_id="unknown-1", score=0.1, latency_ms=1.0)
    ]

    with pytest.raises(ValueError, match="sample IDs"):
        build_benchmark_report(
            records=records,
            methods={
                method_id: MethodReportInput(
                    display_name=method_id,
                    predictions=predictions,
                    threshold=0.5,
                    low_fpr_threshold=0.8,
                    profile={"threshold": 0.5},
                    include_localization=method_id == "entropy_cpd",
                )
                for method_id in ("global_nll", "window_nll", "entropy_cpd")
            },
            provenance={},
            expected_families=(),
        )
