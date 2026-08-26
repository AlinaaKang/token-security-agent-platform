from __future__ import annotations

import pytest

from app.evaluation.normalize import CPDonlineAdapter
from scripts.benchmark_cpdonline import (
    _baseline_predictions,
    build_parser,
    normalize_unique_rows,
    safe_exception_detail,
    validate_input_paths,
)
from app.evaluation.methods import MethodProfile
from app.evaluation.normalize import PromptRecord
from app.model.runtime import ModelObservation
from app.model.token_stats import ObservedUserToken
from scripts.calibrate_model import main as legacy_calibration_main


def test_benchmark_parser_requires_all_sources_and_outputs() -> None:
    args = build_parser().parse_args(
        [
            "--model-path",
            "Qwen/Qwen2.5-7B-Instruct",
            "--autodan-csv",
            "pyproject.toml",
            "--advprompter-csv",
            "pyproject.toml",
            "--gcg-csv",
            "pyproject.toml",
            "--output-dir",
            "tmp/results",
            "--version",
            "paper-compatible-v1",
            "--source-commit",
            "0123456789abcdef",
        ]
    )

    validate_input_paths(args)
    assert args.max_input_tokens == 4096
    assert args.source_commit == "0123456789abcdef"


def test_benchmark_rejects_missing_source_before_model_load() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "--model-path",
            "model",
            "--autodan-csv",
            "missing-autodan.csv",
            "--advprompter-csv",
            "missing-adv.csv",
            "--gcg-csv",
            "missing-gcg.csv",
            "--output-dir",
            "tmp/results",
            "--version",
            "paper-compatible-v1",
            "--source-commit",
            "0123456789abcdef",
        ]
    )

    with pytest.raises(FileNotFoundError, match="autodan_csv"):
        validate_input_paths(args)


def test_legacy_unlabeled_calibration_entry_point_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.argv", ["calibrate_model.py"])

    with pytest.raises(SystemExit, match="benchmark_cpdonline.py"):
        legacy_calibration_main()


def test_benchmark_deduplicates_identical_canonical_records() -> None:
    row = {
        "full_prompt": "Summarize this safe report. appended-pattern",
        "suffix": " appended-pattern",
        "is_adversarial": "True",
        "algorithm": "AutoDAN",
    }

    records, duplicate_count = normalize_unique_rows(
        [row, dict(row)],
        CPDonlineAdapter("cpdonline/test"),
    )

    assert len(records) == 1
    assert duplicate_count == 1


def test_safe_validation_detail_excludes_rejected_input() -> None:
    with pytest.raises(Exception) as captured:
        from app.model.runtime import ModelObservation

        ModelObservation(
            model_id="model",
            tokenizer_id="tokenizer",
            system_prompt_hash="sha256:system",
            system_entropies=(),
            user_tokens=(),
            latency_ms=1.0,
        )

    detail = safe_exception_detail(captured.value)

    assert "system_entropies" in detail
    assert "too_short" in detail
    assert "sha256:system" not in detail


def test_baseline_predictions_preserve_ids_without_claiming_localization() -> None:
    record = PromptRecord(
        sample_id="safe-1",
        prompt="SAFE_TEXT",
        label_suffix_attack=False,
        source_dataset="synthetic-safe",
        group_id="safe-group",
    )
    observation = ModelObservation(
        model_id="model",
        tokenizer_id="tokenizer",
        system_prompt_hash="sha256:system",
        system_entropies=(1.0,),
        user_tokens=(
            ObservedUserToken(
                user_index=0,
                full_index=1,
                token_id=10,
                token_text="SAFE",
                char_start=0,
                char_end=4,
                entropy=1.0,
                nll=2.0,
            ),
        ),
        latency_ms=3.0,
    )
    profile = MethodProfile(
        method_id="global_nll",
        threshold=1.5,
        low_fpr_threshold=2.5,
    )

    predictions = _baseline_predictions([record], [observation], profile)

    assert predictions[0].sample_id == "safe-1"
    assert predictions[0].score == 2.0
    assert predictions[0].alarm_index is None
    assert predictions[0].onset_char_start is None
