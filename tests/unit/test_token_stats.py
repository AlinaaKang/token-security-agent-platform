from __future__ import annotations

import math

import pytest

from app.model.token_stats import (
    TokenStatistic,
    compute_next_token_stats,
    entropy_from_logits,
    project_span_statistics,
    project_user_tokens,
    sanitize_entropy,
)


def test_entropy_matches_hand_computed_three_class_distribution() -> None:
    entropy = entropy_from_logits([0.0, math.log(2.0), 0.0])

    expected = -(
        0.25 * math.log(0.25)
        + 0.5 * math.log(0.5)
        + 0.25 * math.log(0.25)
    )
    assert entropy == pytest.approx(expected)


def test_nll_uses_previous_position_to_score_observed_token() -> None:
    token_ids = [2, 1, 0]
    logits = [
        [0.0, math.log(2.0), 0.0],
        [math.log(4.0), 0.0, 0.0],
    ]

    stats = compute_next_token_stats(logits, token_ids)

    assert [stat.full_index for stat in stats] == [1, 2]
    assert stats[0].nll == pytest.approx(math.log(2.0))
    assert stats[1].nll == pytest.approx(math.log(1.5))


def test_user_projection_excludes_system_and_control_tokens() -> None:
    token_ids = [100, 10, 11, 200]
    token_texts = ["system", "hello", " world", "control"]
    offsets = [(0, 6), (7, 12), (12, 18), (19, 26)]
    logits = [
        [0.0] * 201,
        [0.0] * 201,
        [0.0] * 201,
    ]
    stats = compute_next_token_stats(logits, token_ids)

    user_tokens = project_user_tokens(
        token_ids=token_ids,
        token_texts=token_texts,
        offsets=offsets,
        statistics=stats,
        user_char_span=(7, 18),
    )

    assert [token.token_id for token in user_tokens] == [10, 11]
    assert [token.user_index for token in user_tokens] == [0, 1]
    assert [(token.char_start, token.char_end) for token in user_tokens] == [
        (0, 5),
        (5, 11),
    ]


def test_span_projection_selects_only_tokens_inside_requested_segment() -> None:
    offsets = [(0, 6), (7, 12), (12, 18), (19, 26)]
    statistics = [
        TokenStatistic(full_index=1, entropy=1.0, nll=1.0),
        TokenStatistic(full_index=2, entropy=2.0, nll=2.0),
        TokenStatistic(full_index=3, entropy=3.0, nll=3.0),
    ]

    projected = project_span_statistics(
        offsets=offsets,
        statistics=statistics,
        char_span=(7, 18),
    )

    assert [item.full_index for item in projected] == [1, 2]


def test_entropy_sanitizer_clamps_only_float_roundoff() -> None:
    assert sanitize_entropy(-1e-7) == 0.0
    assert sanitize_entropy(0.25) == 0.25

    with pytest.raises(ValueError, match="negative entropy"):
        sanitize_entropy(-0.1)
