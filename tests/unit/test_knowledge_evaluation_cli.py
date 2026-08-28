from __future__ import annotations

import json
import shutil
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.evaluate_knowledge import run_evaluation


@pytest.fixture
def workspace_tmp_path() -> Path:
    path = Path("tmp") / f"knowledge-eval-{uuid4().hex}"
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_cli_writes_aggregate_ascii_report_without_fixture_terms(
    workspace_tmp_path: Path,
) -> None:
    fixture = workspace_tmp_path / "fixture.json"
    output = workspace_tmp_path / "report.json"
    fixture.write_text(
        json.dumps(
            [
                {
                    "case_id": "safe-case-01",
                    "risk_domain": "jailbreak",
                    "safe_terms": ["LLM jailbreak", "安全绕过"],
                    "metadata": {
                        "semantic_severity": "unsafe",
                        "semantic_categories": ["jailbreak"],
                        "detector_status": "token_anomaly_candidate",
                        "fusion_reason": "semantic_unsafe",
                        "decision": "block",
                        "mode": "analysis",
                        "attack_family": "GCG"
                    },
                    "expected_any_ids": ["mitre-atlas-jailbreak"]
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    report = run_evaluation(
        snapshot_path=Path("knowledge/snapshots/official-v1"),
        fixture_path=fixture,
        output_path=output,
        split="test",
    )

    serialized = output.read_text(encoding="ascii")
    assert report.split == "test"
    assert report.hit_at_3 == 1.0
    assert "LLM jailbreak" not in serialized
    assert "safe-case-01" not in serialized
    assert "safe_terms" not in serialized
    assert "query_text" not in serialized
    assert "case_id" not in serialized
