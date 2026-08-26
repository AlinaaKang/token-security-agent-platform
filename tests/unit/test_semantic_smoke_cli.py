from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.smoke_semantic_guard import run_smoke


class FakeClient:
    def __init__(self) -> None:
        self.responses = [
            {
                "semantic_severity": "safe",
                "semantic_categories": [],
                "semantic_model_version": "guard-v1",
                "decision": "allow",
                "detector_status": "no_token_anomaly",
                "fusion_reason": "all_clear",
                "latency_ms": 10.0,
                "signals": [{"token_text": "SAFE_TOKEN_TEXT"}],
                "guard_raw_output": "Safety: Safe\nCategories: None",
            },
            {
                "semantic_severity": "controversial",
                "semantic_categories": ["politically_sensitive"],
                "semantic_model_version": "guard-v1",
                "decision": "review",
                "detector_status": "token_anomaly_candidate",
                "fusion_reason": "semantic_controversial",
                "latency_ms": 12.0,
                "signals": [],
            },
        ]

    def get_json(self, url: str) -> dict:
        return {
            "model": {"ready": True, "model_id": "qwen-model"},
            "semantic_guard": {
                "ready": True,
                "model_id": "qwen-guard",
                "model_version": "guard-v1",
            },
        }

    def post_json(self, url: str, payload: dict) -> dict:
        return self.responses.pop(0)


def write_safe_input(path: Path) -> None:
    rows = [
        {
            "sample_id": "safe-1",
            "prompt": "SAFE_PRIVATE_FIXTURE_ONE",
            "mode": "analysis",
            "expected_semantic": "safe",
            "expected_action": "allow",
        },
        {
            "sample_id": "safe-2",
            "prompt": "SAFE_PRIVATE_FIXTURE_TWO",
            "mode": "gateway",
            "expected_semantic": "controversial",
            "expected_action": "review",
        },
    ]
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_smoke_report_contains_only_aggregate_normalized_evidence() -> None:
    input_path = Path("tmp/test-semantic-smoke-protected.jsonl")
    output_path = Path("tmp/test-semantic-smoke-aggregate.json")
    input_path.parent.mkdir(exist_ok=True)
    write_safe_input(input_path)

    try:
        report = run_smoke(
            input_path=input_path,
            api_base="http://127.0.0.1:18000",
            output_path=output_path,
            expected_model_version="guard-v1",
            client=FakeClient(),
        )
        serialized = output_path.read_text(encoding="utf-8")
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)

    assert report["sample_count"] == 2
    assert report["returned_semantic"] == {"controversial": 1, "safe": 1}
    assert report["actions"] == {"allow": 1, "review": 1}
    assert report["detector_statuses"] == {
        "no_token_anomaly": 1,
        "token_anomaly_candidate": 1,
    }
    assert report["fusion_reasons"] == {
        "all_clear": 1,
        "semantic_controversial": 1,
    }
    assert report["evidence_combinations"] == {
        "controversial|token_anomaly_candidate|semantic_controversial|review": 1,
        "safe|no_token_anomaly|all_clear|allow": 1,
    }
    assert report["expectation_matches"] == {"action": 2, "semantic": 2}
    assert report["guard_model_versions"] == {"guard-v1": 2}
    assert "SAFE_PRIVATE_FIXTURE" not in serialized
    assert "SAFE_TOKEN_TEXT" not in serialized
    assert "Safety: Safe" not in serialized
    assert "guard_raw_output" not in serialized
    assert "prompt" not in serialized.casefold()


def test_smoke_rejects_duplicate_ids_before_calling_api() -> None:
    input_path = Path("tmp/test-semantic-smoke-duplicate.jsonl")
    output_path = Path("tmp/test-semantic-smoke-duplicate-output.json")
    input_path.parent.mkdir(exist_ok=True)
    row = {"sample_id": "safe-1", "prompt": "SAFE_PRIVATE_FIXTURE"}
    input_path.write_text(
        json.dumps(row) + "\n" + json.dumps(row) + "\n",
        encoding="utf-8",
    )

    try:
        with pytest.raises(ValueError, match="unique"):
            run_smoke(
                input_path=input_path,
                api_base="http://127.0.0.1:18000",
                output_path=output_path,
                expected_model_version="guard-v1",
                client=FakeClient(),
            )
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
