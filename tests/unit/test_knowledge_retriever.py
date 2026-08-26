from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.knowledge.loader import load_knowledge_snapshot
from app.knowledge.query import RetrievalQuery
from app.knowledge.retriever import LocalKnowledgeRetriever


@pytest.fixture(scope="module")
def retriever() -> LocalKnowledgeRetriever:
    snapshot = load_knowledge_snapshot(
        Path("knowledge/snapshots/official-v1")
    )
    return LocalKnowledgeRetriever(snapshot)


def _query(
    *,
    lexical_terms: tuple[str, ...],
    routing_tags: tuple[str, ...],
    query_text: str = "safe synthetic query",
) -> RetrievalQuery:
    return RetrievalQuery(
        query_text=query_text,
        lexical_terms=lexical_terms,
        routing_tags=routing_tags,
        used_prefix_only=False,
    )


def test_retriever_combines_tags_and_lexical_score(
    retriever: LocalKnowledgeRetriever,
) -> None:
    result = retriever.search(
        _query(
            lexical_terms=("prompt", "injection"),
            routing_tags=("jailbreak", "cpd_candidate", "autodan"),
        )
    )

    assert [item.knowledge_id for item in result][:2] == [
        "mitre-atlas-prompt-injection",
        "owasp-llm01-prompt-injection",
    ]
    assert all(item.retrieval_score > 0 for item in result)
    assert "autodan" in result[0].matched_tags


def test_retriever_breaks_equal_tag_scores_by_knowledge_id(
    retriever: LocalKnowledgeRetriever,
) -> None:
    result = retriever.search(
        _query(lexical_terms=(), routing_tags=("governance",)),
        top_k=10,
    )

    assert len(result) == 3
    assert [item.knowledge_id for item in result] == sorted(
        item.knowledge_id for item in result
    )


def test_retriever_uses_lexical_terms_without_routing_tags(
    retriever: LocalKnowledgeRetriever,
) -> None:
    result = retriever.search(
        _query(
            lexical_terms=("sensitive", "information", "disclosure"),
            routing_tags=(),
        )
    )

    assert result[0].knowledge_id == "owasp-llm02-sensitive-information"


def test_retriever_returns_empty_for_unmatched_query(
    retriever: LocalKnowledgeRetriever,
) -> None:
    result = retriever.search(
        _query(lexical_terms=("zzzznotindexed",), routing_tags=("unknown",))
    )

    assert result == []


def test_retriever_supports_fastapi_worker_threads(
    retriever: LocalKnowledgeRetriever,
) -> None:
    query = _query(
        lexical_terms=("prompt", "injection"),
        routing_tags=("jailbreak",),
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(retriever.search, query).result()

    assert result
    assert all(item.knowledge_id for item in result)


def test_retriever_never_serializes_or_indexes_query_text(
    retriever: LocalKnowledgeRetriever,
) -> None:
    private_query = "SAFE_PRIVATE_QUERY"
    result = retriever.search(
        _query(
            lexical_terms=("prompt",),
            routing_tags=("jailbreak",),
            query_text=private_query,
        )
    )

    serialized = "\n".join(item.model_dump_json() for item in result)
    connection = next(
        value
        for value in vars(retriever).values()
        if isinstance(value, sqlite3.Connection)
    )
    index_dump = "\n".join(connection.iterdump())
    assert private_query not in serialized
    assert private_query not in index_dump
    assert private_query not in repr(retriever)


@pytest.mark.parametrize("top_k", [0, -1])
def test_retriever_rejects_non_positive_result_limit(
    retriever: LocalKnowledgeRetriever,
    top_k: int,
) -> None:
    with pytest.raises(ValueError, match="top_k"):
        retriever.search(
            _query(lexical_terms=("prompt",), routing_tags=("jailbreak",)),
            top_k=top_k,
        )
