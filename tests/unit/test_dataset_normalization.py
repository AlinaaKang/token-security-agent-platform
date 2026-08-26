from __future__ import annotations

import pytest

from app.evaluation.normalize import (
    CPDonlineAdapter,
    CPDonlineGuardBypassAdapter,
    CPDonlineOptimizationAdapter,
    DatasetValidationError,
    normalize_rows,
)


def test_cpdonline_attack_row_is_converted_with_suffix_coordinates() -> None:
    adapter = CPDonlineAdapter(dataset_name="cpdonline/full_prompt_dataset")
    row = {
        "full_prompt": "Summarize the quarterly report. appended-pattern",
        "suffix": " appended-pattern",
        "is_adversarial": "True",
        "algorithm": "GCG",
    }

    record = adapter.convert(row)

    assert record.label_suffix_attack is True
    assert record.attack_family == "GCG"
    assert record.suffix_text == " appended-pattern"
    assert record.suffix_char_start == 31
    assert record.group_id.startswith("grp_")


def test_cpdonline_benign_row_has_no_suspicious_span() -> None:
    adapter = CPDonlineAdapter(dataset_name="cpdonline/benign_mix_ppgap1")

    record = adapter.convert(
        {
            "full_prompt": "Explain how rainbows form.",
            "suffix": "",
            "is_adversarial": "False",
            "algorithm": "benign",
            "source_dataset": "xstest",
            "language": "en",
        }
    )

    assert record.label_suffix_attack is False
    assert record.suffix_text is None
    assert record.suffix_char_start is None
    assert record.language == "en"


def test_attack_row_without_suffix_is_rejected() -> None:
    adapter = CPDonlineAdapter(dataset_name="cpdonline/full_prompt_dataset")

    with pytest.raises(DatasetValidationError, match="suffix"):
        adapter.convert(
            {
                "full_prompt": "Summarize the quarterly report.",
                "suffix": "",
                "is_adversarial": "True",
                "algorithm": "GCG",
            }
        )


def test_suffix_must_match_the_end_of_the_full_prompt() -> None:
    adapter = CPDonlineAdapter(dataset_name="cpdonline/full_prompt_dataset")

    with pytest.raises(DatasetValidationError, match="end"):
        adapter.convert(
            {
                "full_prompt": "Summarize the quarterly report.",
                "suffix": "different-pattern",
                "is_adversarial": "True",
                "algorithm": "GCG",
            }
        )


def test_normalization_rejects_duplicate_sample_ids() -> None:
    adapter = CPDonlineAdapter(dataset_name="cpdonline/full_prompt_dataset")
    rows = [
        {
            "full_prompt": "Summarize the quarterly report. appended-pattern",
            "suffix": " appended-pattern",
            "is_adversarial": "True",
            "algorithm": "GCG",
        },
        {
            "full_prompt": "Summarize the quarterly report. appended-pattern",
            "suffix": " appended-pattern",
            "is_adversarial": "True",
            "algorithm": "GCG",
        },
    ]

    with pytest.raises(DatasetValidationError, match="duplicate sample_id"):
        normalize_rows(rows, adapter)


def test_cpdonline_optimization_result_uses_full_instruct_and_suffix() -> None:
    adapter = CPDonlineOptimizationAdapter(
        dataset_name="cpdonline/llama2_7b_foo_opt",
        attack_family="advprompter",
    )

    record = adapter.convert(
        {
            "instruct": "Classify this customer message.",
            "suffix": " appended-pattern",
            "full_instruct": "Classify this customer message. appended-pattern",
        }
    )

    assert record.prompt == "Classify this customer message. appended-pattern"
    assert record.suffix_char_start == 31
    assert record.attack_family == "advprompter"


def test_cpdonline_guard_bypass_concatenates_prompt_and_trigger() -> None:
    adapter = CPDonlineGuardBypassAdapter(dataset_name="cpdonline/gcg_guard_bypass")

    record = adapter.convert(
        {
            "prompt": "Draft a meeting agenda.",
            "trigger": " appended-pattern",
        }
    )

    assert record.prompt == "Draft a meeting agenda. appended-pattern"
    assert record.suffix_text == " appended-pattern"
    assert record.attack_family == "gcg"
