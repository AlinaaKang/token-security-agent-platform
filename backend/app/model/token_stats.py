from __future__ import annotations

import math
from collections.abc import Sequence

from pydantic import BaseModel, Field


class TokenStatistic(BaseModel):
    full_index: int = Field(ge=0)
    entropy: float = Field(ge=0)
    nll: float = Field(ge=0)


class ObservedUserToken(BaseModel):
    user_index: int = Field(ge=0)
    full_index: int = Field(ge=0)
    token_id: int = Field(ge=0)
    token_text: str
    char_start: int = Field(ge=0)
    char_end: int = Field(ge=0)
    entropy: float = Field(ge=0)
    nll: float = Field(ge=0)


def sanitize_entropy(value: float, *, tolerance: float = 1e-5) -> float:
    if not math.isfinite(value):
        raise ValueError("entropy must be finite")
    if value < -tolerance:
        raise ValueError("negative entropy exceeds numerical tolerance")
    return max(0.0, value)


def _logsumexp(logits: Sequence[float]) -> float:
    if not logits:
        raise ValueError("logits must not be empty")
    if not all(math.isfinite(value) for value in logits):
        raise ValueError("logits must contain only finite values")
    maximum = max(logits)
    return maximum + math.log(sum(math.exp(value - maximum) for value in logits))


def entropy_from_logits(logits: Sequence[float]) -> float:
    log_normalizer = _logsumexp(logits)
    return sum(
        math.exp(value - log_normalizer) * (log_normalizer - value)
        for value in logits
    )


def compute_next_token_stats(
    logits: Sequence[Sequence[float]], token_ids: Sequence[int]
) -> list[TokenStatistic]:
    required_positions = max(0, len(token_ids) - 1)
    if len(logits) < required_positions:
        raise ValueError("logits must cover every next-token prediction")

    statistics: list[TokenStatistic] = []
    for token_index in range(1, len(token_ids)):
        prediction_logits = logits[token_index - 1]
        token_id = token_ids[token_index]
        if token_id < 0 or token_id >= len(prediction_logits):
            raise ValueError(f"token id {token_id} is outside the logits vocabulary")
        log_normalizer = _logsumexp(prediction_logits)
        statistics.append(
            TokenStatistic(
                full_index=token_index,
                entropy=entropy_from_logits(prediction_logits),
                nll=log_normalizer - prediction_logits[token_id],
            )
        )
    return statistics


def project_span_statistics(
    *,
    offsets: Sequence[tuple[int, int]],
    statistics: Sequence[TokenStatistic],
    char_span: tuple[int, int],
) -> list[TokenStatistic]:
    span_start, span_end = char_span
    if span_start < 0 or span_end < span_start:
        raise ValueError("character span is invalid")

    statistics_by_index = {stat.full_index: stat for stat in statistics}
    projected: list[TokenStatistic] = []
    for full_index, (char_start, char_end) in enumerate(offsets):
        if char_end <= char_start:
            continue
        if char_start < span_start or char_end > span_end:
            continue
        statistic = statistics_by_index.get(full_index)
        if statistic is not None:
            projected.append(statistic)
    return projected


def project_user_tokens(
    *,
    token_ids: Sequence[int],
    token_texts: Sequence[str],
    offsets: Sequence[tuple[int, int]],
    statistics: Sequence[TokenStatistic],
    user_char_span: tuple[int, int],
) -> list[ObservedUserToken]:
    if not (len(token_ids) == len(token_texts) == len(offsets)):
        raise ValueError("token ids, text and offsets must have equal lengths")
    user_start, user_end = user_char_span
    if user_start < 0 or user_end < user_start:
        raise ValueError("user character span is invalid")

    projected_indices = {
        stat.full_index
        for stat in project_span_statistics(
            offsets=offsets,
            statistics=statistics,
            char_span=user_char_span,
        )
    }
    statistics_by_index = {stat.full_index: stat for stat in statistics}
    user_tokens: list[ObservedUserToken] = []
    for full_index, (token_id, token_text, offset) in enumerate(
        zip(token_ids, token_texts, offsets, strict=True)
    ):
        char_start, char_end = offset
        if full_index not in projected_indices:
            continue
        statistic = statistics_by_index.get(full_index)
        if statistic is None:
            continue
        user_tokens.append(
            ObservedUserToken(
                user_index=len(user_tokens),
                full_index=full_index,
                token_id=token_id,
                token_text=token_text,
                char_start=char_start - user_start,
                char_end=char_end - user_start,
                entropy=statistic.entropy,
                nll=statistic.nll,
            )
        )
    return user_tokens
