from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from app.knowledge.loader import canonical_card_payload, load_knowledge_snapshot
from app.knowledge.models import KnowledgeCard


FORBIDDEN_KEYS = {
    "prompt",
    "suffix",
    "token_text",
    "token_id",
    "raw_output",
    "guard_raw_output",
}


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).casefold() in FORBIDDEN_KEYS or _contains_forbidden_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _ascii_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def build_snapshot(source: Path, output_dir: Path, snapshot_version: str) -> bytes:
    source_data = json.loads(source.read_text(encoding="utf-8"))
    if _contains_forbidden_key(source_data):
        raise ValueError("forbidden knowledge source key")
    if not isinstance(source_data, list) or not source_data:
        raise ValueError("knowledge source must be a non-empty list")

    cards: list[KnowledgeCard] = []
    for raw in source_data:
        candidate = KnowledgeCard.model_validate(
            {**raw, "content_sha256": "sha256:" + "0" * 64}
        )
        digest = "sha256:" + hashlib.sha256(canonical_card_payload(candidate)).hexdigest()
        cards.append(candidate.model_copy(update={"content_sha256": digest}))
    cards.sort(key=lambda card: card.knowledge_id)
    if len({card.knowledge_id for card in cards}) != len(cards):
        raise ValueError("knowledge IDs must be unique")

    cards_bytes = _ascii_json_bytes([card.model_dump(mode="json") for card in cards])
    manifest = {
        "schema_version": 1,
        "snapshot_version": snapshot_version,
        "card_count": len(cards),
        "cards_sha256": "sha256:" + hashlib.sha256(cards_bytes).hexdigest(),
        "publishers": sorted({card.source.publisher.value for card in cards}),
    }
    manifest_bytes = _ascii_json_bytes(manifest)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "cards.json").write_bytes(cards_bytes)
    (output_dir / "manifest.json").write_bytes(manifest_bytes)
    load_knowledge_snapshot(output_dir)
    return cards_bytes + manifest_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an offline knowledge snapshot")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--snapshot-version", required=True)
    args = parser.parse_args()
    build_snapshot(args.source, args.output_dir, args.snapshot_version)
    print(f"knowledge snapshot built version={args.snapshot_version}")


if __name__ == "__main__":
    main()
