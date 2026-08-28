from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from app.knowledge.loader import KnowledgeSnapshotError, load_knowledge_snapshot
from app.knowledge.models import KnowledgePublisher, RiskDomain


@pytest.fixture
def workspace_tmp_path() -> Path:
    path = Path("tmp") / f"knowledge-loader-{uuid4().hex}"
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _card(**overrides: object) -> dict[str, object]:
    card: dict[str, object] = {
        "knowledge_id": "owasp-llm01-prompt-injection",
        "title_zh": "提示词注入风险",
        "risk_domain": "prompt_injection",
        "semantic_categories": ["jailbreak"],
        "detector_tags": ["cpd_candidate"],
        "fusion_tags": ["cpd_candidate"],
        "attack_families": [],
        "summary": "攻击者可能通过输入覆盖应用原有指令边界。",
        "indicators": ["输入试图改变既定指令层级"],
        "recommendations": ["隔离不可信输入并执行多证据研判"],
        "retrieval_tags": ["提示词注入", "prompt injection"],
        "source": {
            "publisher": "owasp",
            "title": "LLM01: Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            "version": "2025",
            "verified_at": "2026-08-26T00:00:00Z",
            "usage_note": "中文转述，原始定义请参阅官方来源。",
        },
    }
    card.update(overrides)
    payload = json.dumps(
        card,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    card["content_sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    return card


def _write_snapshot(path: Path, cards: list[dict[str, object]]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    ordered = sorted(cards, key=lambda item: str(item["knowledge_id"]))
    cards_bytes = (
        json.dumps(
            ordered,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    (path / "cards.json").write_bytes(cards_bytes)
    publishers = sorted(
        {str(card["source"]["publisher"]) for card in ordered}  # type: ignore[index]
    )
    manifest = {
        "schema_version": 1,
        "snapshot_version": "official-v1",
        "card_count": len(ordered),
        "cards_sha256": "sha256:" + hashlib.sha256(cards_bytes).hexdigest(),
        "publishers": publishers,
    }
    (path / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="ascii",
    )


def test_loader_accepts_allowlisted_hashed_card(workspace_tmp_path: Path) -> None:
    _write_snapshot(workspace_tmp_path, [_card()])

    snapshot = load_knowledge_snapshot(workspace_tmp_path)

    assert snapshot.manifest.snapshot_version == "official-v1"
    assert snapshot.cards[0].knowledge_id == "owasp-llm01-prompt-injection"


def test_knowledge_schema_exposes_official_v2_publishers_and_domains() -> None:
    assert KnowledgePublisher.CAC.value == "cac"
    assert {
        RiskDomain.SUPPLY_CHAIN.value,
        RiskDomain.DATA_MODEL_POISONING.value,
        RiskDomain.UNBOUNDED_RESOURCE_CONSUMPTION.value,
    } == {
        "supply_chain",
        "data_model_poisoning",
        "unbounded_resource_consumption",
    }


@pytest.mark.parametrize(
    ("knowledge_id", "publisher", "url"),
    [
        (
            "cac-generative-ai-interim-measures",
            "cac",
            "https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm",
        ),
        (
            "nist-ai-600-1-genai-profile",
            "nist",
            "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf",
        ),
    ],
)
def test_loader_accepts_publisher_specific_official_hosts(
    workspace_tmp_path: Path,
    knowledge_id: str,
    publisher: str,
    url: str,
) -> None:
    card = _card(
        knowledge_id=knowledge_id,
        source={
            "publisher": publisher,
            "title": "Official source",
            "url": url,
            "version": "2025",
            "verified_at": "2026-08-28T00:00:00Z",
            "usage_note": "中文转述，原始定义请参阅官方来源。",
        },
    )
    _write_snapshot(workspace_tmp_path, [card])

    assert load_knowledge_snapshot(workspace_tmp_path).cards[0].source.url == url


@pytest.mark.parametrize(
    ("publisher", "url"),
    [
        ("nist", "https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm"),
        ("cac", "https://example.test/2023-07/13/c_1690898327029107.htm"),
    ],
)
def test_loader_rejects_cac_url_without_matching_publisher_or_host(
    workspace_tmp_path: Path,
    publisher: str,
    url: str,
) -> None:
    card = _card(
        source={
            "publisher": publisher,
            "title": "Official source",
            "url": url,
            "version": "2025",
            "verified_at": "2026-08-28T00:00:00Z",
            "usage_note": "中文转述，原始定义请参阅官方来源。",
        }
    )
    _write_snapshot(workspace_tmp_path, [card])

    with pytest.raises(KnowledgeSnapshotError):
        load_knowledge_snapshot(workspace_tmp_path)


def test_loader_accepts_official_v2_snapshot() -> None:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v2"))

    assert snapshot.manifest.snapshot_version == "official-v2"
    assert snapshot.manifest.card_count == 18
    assert {card.risk_domain.value for card in snapshot.cards} >= {
        "supply_chain",
        "data_model_poisoning",
        "unbounded_resource_consumption",
    }
    assert {card.source.publisher.value for card in snapshot.cards} == {
        "owasp",
        "mitre",
        "nist",
        "cac",
    }


def test_official_v2_uses_current_owasp_canonical_urls() -> None:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v2"))
    urls = {card.knowledge_id: card.source.url for card in snapshot.cards}

    assert urls["owasp-llm03-supply-chain"] == (
        "https://genai.owasp.org/llmrisk/llm032025-supply-chain/"
    )
    assert urls["owasp-llm04-data-model-poisoning"] == (
        "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/"
    )
    assert urls["owasp-llm10-unbounded-consumption"] == (
        "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/"
    )


@pytest.mark.parametrize(
    "mutation",
    ["unknown_field", "duplicate_id", "http_url", "wrong_host", "bad_hash"],
)
def test_loader_rejects_invalid_snapshot(
    workspace_tmp_path: Path,
    mutation: str,
) -> None:
    card = _card()
    cards = [deepcopy(card)]
    if mutation == "unknown_field":
        cards[0]["unexpected"] = "value"
    elif mutation == "duplicate_id":
        cards.append(deepcopy(card))
    elif mutation == "http_url":
        cards[0] = _card(
            source={
                **card["source"],  # type: ignore[arg-type]
                "url": "http://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            }
        )
    elif mutation == "wrong_host":
        cards[0] = _card(
            source={
                **card["source"],  # type: ignore[arg-type]
                "url": "https://example.test/fake-source",
            }
        )
    elif mutation == "bad_hash":
        cards[0]["content_sha256"] = "sha256:" + "0" * 64
    _write_snapshot(workspace_tmp_path, cards)

    with pytest.raises(KnowledgeSnapshotError):
        load_knowledge_snapshot(workspace_tmp_path)


def test_loader_rejects_manifest_hash_mismatch(workspace_tmp_path: Path) -> None:
    _write_snapshot(workspace_tmp_path, [_card()])
    manifest_path = workspace_tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["cards_sha256"] = "sha256:" + "f" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="ascii")

    with pytest.raises(KnowledgeSnapshotError):
        load_knowledge_snapshot(workspace_tmp_path)
