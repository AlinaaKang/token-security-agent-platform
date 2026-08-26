from __future__ import annotations

import pytest

from app.agent.fusion import FusionReason
from app.knowledge.query import RetrievalMetadata, SafeQueryBuilder, SafeQueryError
from app.schemas import Decision
from app.semantic.models import SemanticCategory, SemanticSeverity


def _metadata(**overrides: object) -> RetrievalMetadata:
    values: dict[str, object] = {
        "semantic_severity": SemanticSeverity.UNSAFE,
        "semantic_categories": (SemanticCategory.JAILBREAK,),
        "detector_status": "token_anomaly_candidate",
        "fusion_reason": FusionReason.SEMANTIC_UNSAFE,
        "decision": Decision.BLOCK,
        "mode": "analysis",
        "attack_family": "AutoDAN",
    }
    values.update(overrides)
    return RetrievalMetadata.model_validate(values)


def test_builder_excludes_text_after_cpd_onset() -> None:
    result = SafeQueryBuilder().build(
        "SAFE_PREFIX_PRIVATE_SUFFIX",
        char_onset=len("SAFE_PREFIX_"),
        metadata=_metadata(),
    )

    assert result.query_text == "safe_prefix_"
    assert "PRIVATE_SUFFIX" not in result.query_text
    assert result.used_prefix_only is True


def test_builder_redacts_email_tokens_keys_and_network_addresses() -> None:
    result = SafeQueryBuilder().build(
        "contact SAFE_USER@example.test token=SAFE_SECRET "
        "Bearer SAFE_BEARER -----BEGIN PRIVATE KEY----- "
        "10.20.30.40 2001:db8::1 customer=123456789",
        char_onset=None,
        metadata=_metadata(),
    )

    serialized = result.query_text
    for private_value in (
        "SAFE_USER",
        "SAFE_SECRET",
        "SAFE_BEARER",
        "PRIVATE KEY",
        "10.20.30.40",
        "2001:db8::1",
        "123456789",
    ):
        assert private_value.casefold() not in serialized
    assert "redacted" in serialized


def test_builder_truncates_before_redaction_and_never_exposes_query_in_repr() -> None:
    private_tail = "SAFE_PRIVATE_TAIL"
    result = SafeQueryBuilder(max_characters=16).build(
        "abcdefghijklmnop" + private_tail,
        char_onset=None,
        metadata=_metadata(),
    )

    assert result.query_text == "abcdefghijklmnop"
    assert private_tail not in repr(result)
    assert "query_text" not in result.model_dump()


def test_builder_derives_deduplicated_routing_tags_and_chinese_bigrams() -> None:
    result = SafeQueryBuilder().build(
        "提示词注入风险 prompt injection prompt",
        char_onset=None,
        metadata=_metadata(
            semantic_categories=(
                SemanticCategory.JAILBREAK,
                SemanticCategory.JAILBREAK,
            )
        ),
    )

    assert result.routing_tags == (
        "unsafe",
        "jailbreak",
        "token_anomaly_candidate",
        "semantic_unsafe",
        "block",
        "analysis",
        "autodan",
    )
    assert result.lexical_terms.count("prompt") == 1
    assert "提示" in result.lexical_terms
    assert "示词" in result.lexical_terms
    assert "词注" in result.lexical_terms


@pytest.mark.parametrize("char_onset", [None, 0, -1, 99])
def test_builder_does_not_slice_for_invalid_or_missing_onset(
    char_onset: int | None,
) -> None:
    result = SafeQueryBuilder().build(
        "keep complete text",
        char_onset=char_onset,
        metadata=_metadata(),
    )

    assert result.query_text == "keep complete text"
    assert result.used_prefix_only is False


@pytest.mark.parametrize("prompt", ["", "   \t\n"])
def test_builder_rejects_blank_input_without_echoing_it(prompt: str) -> None:
    with pytest.raises(SafeQueryError) as captured:
        SafeQueryBuilder().build(prompt, char_onset=None, metadata=_metadata())

    assert str(captured.value) == "invalid safe query input"
