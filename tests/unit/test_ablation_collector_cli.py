from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.collect_agent_ablation import collect_observations


class FakeClient:
    def __init__(self, *, calibration: str = "cpd-v1", fail_once: bool = False) -> None:
        self.calibration = calibration
        self.fail_once = fail_once
        self.calls: list[dict] = []

    def get_json(self, url: str) -> dict:
        return {
            "model": {"ready": True, "model_id": "qwen-model"},
            "detector": {"ready": True, "calibration_version": self.calibration},
            "semantic_guard": {
                "ready": True,
                "model_id": "guard-model",
                "model_version": "guard-v1",
            },
        }

    def post_json(self, url: str, payload: dict) -> dict:
        self.calls.append(payload)
        if self.fail_once:
            self.fail_once = False
            raise TimeoutError("SAFE_PRIVATE_PROMPT_ONE")
        index = len(self.calls)
        return {
            "detector_score": 0.8 if index == 1 else 0.2,
            "detector_status": (
                "token_anomaly_candidate" if index == 1 else "no_token_anomaly"
            ),
            "semantic_severity": "safe" if index == 1 else "unsafe",
            "semantic_verification": "performed",
            "semantic_latency_ms": 2.0,
            "latency_ms": 10.0,
            "suspicious_span": (
                {"char_start": 12, "char_end": 20, "token_start": 4, "token_end": 7}
                if index == 1
                else None
            ),
            "prompt": payload["prompt"],
            "signals": [{"token_text": "SAFE_PRIVATE_TOKEN"}],
            "raw_output": "SAFE_PRIVATE_RAW_OUTPUT",
            "knowledge_evidence": [{"summary": "SAFE_PRIVATE_KNOWLEDGE"}],
        }


def _paths(name: str) -> tuple[Path, Path]:
    root = Path("tmp")
    root.mkdir(exist_ok=True)
    return root / f"{name}-input.jsonl", root / f"{name}-observations.jsonl"


def _write_input(path: Path, *, duplicate: bool = False) -> None:
    rows = [
        {
            "sample_id": "suffix-1",
            "group_id": "group-suffix",
            "split": "dev",
            "domain": "optimized_suffix",
            "label_risky": True,
            "attack_family": "gcg",
            "suffix_start": 10,
            "suffix_end": 23,
            "prompt": "SAFE_PRIVATE_PROMPT_ONE",
        },
        {
            "sample_id": "semantic-1",
            "group_id": "group-semantic",
            "split": "dev",
            "domain": "semantic_unsafe",
            "label_risky": True,
            "attack_family": None,
            "suffix_start": None,
            "suffix_end": None,
            "prompt": "SAFE_PRIVATE_PROMPT_TWO",
        },
    ]
    if duplicate:
        rows[1]["sample_id"] = rows[0]["sample_id"]
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )


def _cleanup(input_path: Path, output_path: Path) -> None:
    for path in (
        input_path,
        output_path,
        output_path.with_suffix(output_path.suffix + ".meta.json"),
        output_path.with_suffix(output_path.suffix + ".errors.json"),
    ):
        path.unlink(missing_ok=True)


def test_collector_writes_only_normalized_observations() -> None:
    input_path, output_path = _paths("ablation-collector-private")
    _write_input(input_path)
    client = FakeClient()
    try:
        summary = collect_observations(
            input_path=input_path,
            api_base="http://127.0.0.1:18000",
            output_path=output_path,
            model_id="qwen-model",
            resume=False,
            client=client,
        )
        serialized = output_path.read_text(encoding="utf-8")
        rows = [json.loads(line) for line in serialized.splitlines()]
    finally:
        _cleanup(input_path, output_path)

    assert summary == {"requested": 2, "completed": 2, "failed": 0, "skipped": 0}
    assert len(rows) == 2
    assert rows[0]["sample_id"] == "suffix-1"
    assert rows[0]["predicted_onset"] == 12
    assert rows[0]["production_cpd_alarm"] is True
    assert rows[1]["semantic_severity"] == "unsafe"
    assert all(call["knowledge_mode"] == "off" for call in client.calls)
    assert all(call["mode"] == "analysis" for call in client.calls)
    assert "SAFE_PRIVATE" not in serialized
    assert "prompt" not in serialized.casefold()
    assert "token_text" not in serialized


def test_collector_resume_retries_failures_and_skips_completed_rows() -> None:
    input_path, output_path = _paths("ablation-collector-resume")
    _write_input(input_path)
    first = FakeClient(fail_once=True)
    second = FakeClient()
    try:
        first_summary = collect_observations(
            input_path=input_path, api_base="http://127.0.0.1:18000",
            output_path=output_path, model_id="qwen-model", resume=False,
            client=first,
        )
        second_summary = collect_observations(
            input_path=input_path, api_base="http://127.0.0.1:18000",
            output_path=output_path, model_id="qwen-model", resume=True,
            client=second,
        )
        errors = output_path.with_suffix(output_path.suffix + ".errors.json").read_text(
            encoding="utf-8"
        )
    finally:
        _cleanup(input_path, output_path)

    assert first_summary == {"requested": 2, "completed": 1, "failed": 1, "skipped": 0}
    assert second_summary == {"requested": 2, "completed": 2, "failed": 0, "skipped": 1}
    assert len(second.calls) == 1
    assert "SAFE_PRIVATE_PROMPT" not in errors


def test_collector_rejects_resume_identity_mismatch_before_requests() -> None:
    input_path, output_path = _paths("ablation-collector-identity")
    _write_input(input_path)
    try:
        collect_observations(
            input_path=input_path, api_base="http://127.0.0.1:18000",
            output_path=output_path, model_id="qwen-model", resume=False,
            client=FakeClient(),
        )
        mismatch = FakeClient(calibration="cpd-v2")
        with pytest.raises(RuntimeError, match="deployment identity mismatch"):
            collect_observations(
                input_path=input_path, api_base="http://127.0.0.1:18000",
                output_path=output_path, model_id="qwen-model", resume=True,
                client=mismatch,
            )
    finally:
        _cleanup(input_path, output_path)

    assert mismatch.calls == []


def test_collector_rejects_duplicate_ids_without_private_error_text() -> None:
    input_path, output_path = _paths("ablation-collector-duplicate")
    _write_input(input_path, duplicate=True)
    client = FakeClient()
    try:
        with pytest.raises(ValueError, match="unique") as error:
            collect_observations(
                input_path=input_path, api_base="http://127.0.0.1:18000",
                output_path=output_path, model_id="qwen-model", resume=False,
                client=client,
            )
    finally:
        _cleanup(input_path, output_path)

    assert "SAFE_PRIVATE" not in str(error.value)
    assert client.calls == []
