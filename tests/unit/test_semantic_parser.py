from __future__ import annotations

import pytest

from app.semantic.models import SemanticCategory, SemanticSeverity
from app.semantic.parser import SemanticOutputError, parse_guard_output


def test_parses_unsafe_guard_output_and_preserves_category_order() -> None:
    result = parse_guard_output(
        "Safety: Unsafe\nCategories: Violent, Jailbreak, Violent",
        model_id="guard-model",
        model_version="guard-v1",
        latency_ms=12.0,
    )

    assert result.severity is SemanticSeverity.UNSAFE
    assert result.categories == [
        SemanticCategory.VIOLENT,
        SemanticCategory.JAILBREAK,
    ]
    assert result.model_id == "guard-model"
    assert result.model_version == "guard-v1"
    assert result.latency_ms == 12.0


def test_parses_safe_guard_output_only_with_no_categories() -> None:
    result = parse_guard_output(
        "  Safety: Safe  \n  Categories: None  ",
        model_id="guard-model",
        model_version="guard-v1",
        latency_ms=1.0,
    )

    assert result.severity is SemanticSeverity.SAFE
    assert result.categories == []


def test_parses_controversial_guard_output() -> None:
    result = parse_guard_output(
        "Safety: Controversial\nCategories: Politically Sensitive Topics",
        model_id="guard-model",
        model_version="guard-v1",
        latency_ms=1.0,
    )

    assert result.severity is SemanticSeverity.CONTROVERSIAL
    assert result.categories == [SemanticCategory.POLITICALLY_SENSITIVE]


@pytest.mark.parametrize(
    ("official_label", "expected"),
    [
        ("Violent", SemanticCategory.VIOLENT),
        ("Non-violent Illegal Acts", SemanticCategory.NON_VIOLENT_ILLEGAL_ACTS),
        ("Sexual Content or Sexual Acts", SemanticCategory.SEXUAL_CONTENT),
        ("PII", SemanticCategory.PII),
        ("Suicide & Self-Harm", SemanticCategory.SUICIDE_SELF_HARM),
        ("Unethical Acts", SemanticCategory.UNETHICAL_ACTS),
        (
            "Politically Sensitive Topics",
            SemanticCategory.POLITICALLY_SENSITIVE,
        ),
        ("Copyright Violation", SemanticCategory.COPYRIGHT_VIOLATION),
        ("Jailbreak", SemanticCategory.JAILBREAK),
    ],
)
def test_maps_each_official_category_label(
    official_label: str,
    expected: SemanticCategory,
) -> None:
    result = parse_guard_output(
        f"Safety: Unsafe\nCategories: {official_label}",
        model_id="guard-model",
        model_version="guard-v1",
        latency_ms=1.0,
    )

    assert result.categories == [expected]


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "Safety: Unknown\nCategories: None",
        "Safety: Safe\nCategories: Unknown Category",
        "Safety: Safe",
        "Safety: Safe\nCategories: None\nExplanation: extra output",
        "Safety: Safe\nCategories: Violent",
        "Safety: Unsafe\nCategories: None",
    ],
)
def test_rejects_untrusted_guard_output_without_echoing_it(raw: str) -> None:
    with pytest.raises(SemanticOutputError) as exc_info:
        parse_guard_output(
            raw,
            model_id="guard-model",
            model_version="guard-v1",
            latency_ms=1.0,
        )

    if raw:
        assert raw not in str(exc_info.value)
