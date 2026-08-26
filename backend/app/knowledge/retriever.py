from __future__ import annotations

import sqlite3
from threading import Lock

from app.knowledge.models import (
    KnowledgeCard,
    KnowledgeEvidence,
    KnowledgeSnapshot,
)
from app.knowledge.query import RetrievalQuery, lexical_terms


class KnowledgeDependencyError(RuntimeError):
    """Raised when the local SQLite runtime does not provide FTS5."""


def _card_routing_tags(card: KnowledgeCard) -> frozenset[str]:
    return frozenset(
        {
            card.risk_domain.value,
            *(category.value for category in card.semantic_categories),
            *card.detector_tags,
            *(reason.value for reason in card.fusion_tags),
            *(family.casefold() for family in card.attack_families),
        }
    )


def _card_lexical_text(card: KnowledgeCard) -> str:
    source_text = " ".join(
        (
            card.knowledge_id,
            card.title_zh,
            card.summary,
            *card.indicators,
            *card.recommendations,
            *card.retrieval_tags,
            card.source.title,
        )
    ).casefold()
    return " ".join(lexical_terms(source_text))


def _fts_expression(terms: tuple[str, ...]) -> str:
    return " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


class LocalKnowledgeRetriever:
    def __init__(
        self,
        snapshot: KnowledgeSnapshot,
        tag_weight: float = 2.0,
        lexical_weight: float = 1.0,
    ) -> None:
        if tag_weight < 0 or lexical_weight < 0:
            raise ValueError("retrieval weights must be non-negative")
        self._snapshot = snapshot
        self._tag_weight = tag_weight
        self._lexical_weight = lexical_weight
        self._cards = {card.knowledge_id: card for card in snapshot.cards}
        self._tags = {
            card.knowledge_id: _card_routing_tags(card) for card in snapshot.cards
        }
        self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._query_lock = Lock()
        try:
            self._connection.execute(
                "CREATE VIRTUAL TABLE knowledge_fts USING fts5("
                "knowledge_id UNINDEXED, lexical_text, tokenize='unicode61')"
            )
            self._connection.executemany(
                "INSERT INTO knowledge_fts(knowledge_id, lexical_text) VALUES (?, ?)",
                [
                    (card.knowledge_id, _card_lexical_text(card))
                    for card in snapshot.cards
                ],
            )
            self._connection.commit()
            self._connection.execute("PRAGMA query_only=ON")
        except sqlite3.OperationalError as exc:
            self._connection.close()
            raise KnowledgeDependencyError("sqlite fts5 unavailable") from exc

    def __repr__(self) -> str:
        return (
            "LocalKnowledgeRetriever("
            f"snapshot_version={self._snapshot.manifest.snapshot_version!r}, "
            f"card_count={len(self._cards)})"
        )

    def _lexical_scores(self, terms: tuple[str, ...]) -> dict[str, float]:
        if not terms:
            return {}
        with self._query_lock:
            rows = self._connection.execute(
                "SELECT knowledge_id, bm25(knowledge_fts) AS rank "
                "FROM knowledge_fts WHERE knowledge_fts MATCH ?",
                (_fts_expression(terms),),
            ).fetchall()
        strengths = {str(row[0]): max(0.0, -float(row[1])) for row in rows}
        maximum = max(strengths.values(), default=0.0)
        if maximum <= 0:
            return {knowledge_id: 1.0 for knowledge_id in strengths}
        return {
            knowledge_id: min(1.0, strength / maximum)
            for knowledge_id, strength in strengths.items()
        }

    def search(
        self,
        query: RetrievalQuery,
        *,
        top_k: int = 3,
    ) -> list[KnowledgeEvidence]:
        if top_k <= 0:
            raise ValueError("top_k must be positive")
        query_tags = frozenset(query.routing_tags)
        lexical_scores = self._lexical_scores(query.lexical_terms)
        scored: list[tuple[float, str, tuple[str, ...]]] = []
        for knowledge_id, card_tags in self._tags.items():
            matched_tags = tuple(sorted(query_tags & card_tags))
            tag_score = len(matched_tags) / max(len(query_tags), 1)
            lexical_score = lexical_scores.get(knowledge_id, 0.0)
            combined = self._tag_weight * tag_score + self._lexical_weight * lexical_score
            if combined > 0:
                scored.append((combined, knowledge_id, matched_tags))
        scored.sort(key=lambda item: (-item[0], item[1]))

        evidence: list[KnowledgeEvidence] = []
        for score, knowledge_id, matched_tags in scored[: min(top_k, 3)]:
            card = self._cards[knowledge_id]
            evidence.append(
                KnowledgeEvidence(
                    knowledge_id=knowledge_id,
                    title_zh=card.title_zh,
                    risk_domain=card.risk_domain,
                    summary=card.summary,
                    recommendations=card.recommendations,
                    source=card.source,
                    retrieval_score=round(score, 6),
                    matched_tags=matched_tags,
                )
            )
        return evidence
