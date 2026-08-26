from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from app.knowledge.models import KnowledgeCard, KnowledgeManifest, KnowledgeSnapshot


class KnowledgeSnapshotError(ValueError):
    """Raised with a fixed message when a knowledge snapshot is invalid."""


def canonical_card_payload(card: KnowledgeCard) -> bytes:
    payload = card.model_dump(mode="json", exclude={"content_sha256"})
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_knowledge_snapshot(path: Path) -> KnowledgeSnapshot:
    try:
        cards_bytes = (path / "cards.json").read_bytes()
        manifest_raw = json.loads((path / "manifest.json").read_text(encoding="ascii"))
        cards_raw = json.loads(cards_bytes.decode("ascii"))
        manifest = KnowledgeManifest.model_validate(manifest_raw)
        cards = tuple(KnowledgeCard.model_validate(item) for item in cards_raw)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValidationError) as exc:
        raise KnowledgeSnapshotError("invalid knowledge snapshot") from exc

    ids = [card.knowledge_id for card in cards]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise KnowledgeSnapshotError("invalid knowledge snapshot ordering")
    if manifest.card_count != len(cards):
        raise KnowledgeSnapshotError("invalid knowledge snapshot count")
    if manifest.cards_sha256 != _sha256(cards_bytes):
        raise KnowledgeSnapshotError("invalid knowledge snapshot hash")
    if any(card.content_sha256 != _sha256(canonical_card_payload(card)) for card in cards):
        raise KnowledgeSnapshotError("invalid knowledge card hash")
    publishers = tuple(sorted({card.source.publisher for card in cards}, key=str))
    if manifest.publishers != publishers:
        raise KnowledgeSnapshotError("invalid knowledge snapshot publishers")
    return KnowledgeSnapshot(manifest=manifest, cards=cards)
