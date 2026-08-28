from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from uuid import uuid4

import pytest

from app.knowledge.loader import load_knowledge_snapshot
from scripts.build_knowledge_snapshot import build_snapshot


@pytest.fixture
def workspace_tmp_path() -> Path:
    path = Path("tmp") / f"knowledge-builder-{uuid4().hex}"
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _source_card() -> dict[str, object]:
    return {
        "knowledge_id": "nist-ai-rmf-govern",
        "title_zh": "治理职责与风险文化",
        "risk_domain": "governance",
        "semantic_categories": [],
        "detector_tags": ["no_token_anomaly"],
        "fusion_tags": ["all_clear"],
        "attack_families": [],
        "summary": "组织需要明确人工智能风险治理职责和问责关系。",
        "indicators": ["缺少明确的风险所有者"],
        "recommendations": ["记录风险责任、审批边界和复核流程"],
        "retrieval_tags": ["治理", "govern"],
        "source": {
            "publisher": "nist",
            "title": "AI RMF 1.0",
            "url": "https://www.nist.gov/itl/ai-risk-management-framework",
            "version": "1.0",
            "verified_at": "2026-08-26T00:00:00Z",
            "usage_note": "中文转述，原始定义请参阅官方来源。",
        },
    }


def test_snapshot_builder_produces_reproducible_valid_output(
    workspace_tmp_path: Path,
) -> None:
    source = workspace_tmp_path / "source.json"
    source.write_text(json.dumps([_source_card()], ensure_ascii=False), encoding="utf-8")

    first = build_snapshot(source, workspace_tmp_path / "one", "official-v1")
    second = build_snapshot(source, workspace_tmp_path / "two", "official-v1")

    assert first == second
    assert (workspace_tmp_path / "one" / "cards.json").read_bytes() == (
        workspace_tmp_path / "two" / "cards.json"
    ).read_bytes()
    assert load_knowledge_snapshot(workspace_tmp_path / "one").manifest.card_count == 1


def test_snapshot_builder_writes_lf_bytes_with_a_valid_manifest_hash(
    workspace_tmp_path: Path,
) -> None:
    source = workspace_tmp_path / "source.json"
    source.write_text(json.dumps([_source_card()], ensure_ascii=False), encoding="utf-8")

    build_snapshot(source, workspace_tmp_path / "snapshot", "official-v1")

    snapshot_dir = workspace_tmp_path / "snapshot"
    cards_bytes = (snapshot_dir / "cards.json").read_bytes()
    manifest_bytes = (snapshot_dir / "manifest.json").read_bytes()
    assert cards_bytes.endswith(b"\n")
    assert manifest_bytes.endswith(b"\n")
    assert b"\r\n" not in cards_bytes
    assert b"\r\n" not in manifest_bytes
    assert load_knowledge_snapshot(snapshot_dir).manifest.cards_sha256 == (
        "sha256:" + hashlib.sha256(cards_bytes).hexdigest()
    )


@pytest.mark.parametrize(
    "forbidden_key",
    ["prompt", "suffix", "token_text", "token_id", "raw_output", "guard_raw_output"],
)
def test_snapshot_builder_rejects_forbidden_keys(
    workspace_tmp_path: Path,
    forbidden_key: str,
) -> None:
    card = _source_card()
    card[forbidden_key] = "SAFE_PRIVATE_VALUE"
    source = workspace_tmp_path / "source.json"
    source.write_text(json.dumps([card], ensure_ascii=False), encoding="utf-8")

    with pytest.raises(ValueError, match="forbidden"):
        build_snapshot(source, workspace_tmp_path / "snapshot", "official-v1")

    assert not (workspace_tmp_path / "snapshot" / "cards.json").exists()
