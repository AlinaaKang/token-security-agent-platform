from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.evaluation.ablation import AblationObservation
from app.evaluation.ablation_io import (
    AblationBenchmarkManifest,
    AblationSplitManifest,
    SourceRevision,
    write_ascii_json,
)
from scripts.evaluate_agent_ablation import evaluate_test
from scripts.select_ablation_profiles import select_profiles


HASH = "sha256:" + "a" * 64


def _paths(name: str) -> dict[str, Path]:
    root = Path("tmp")
    root.mkdir(exist_ok=True)
    return {
        key: root / f"{name}-{key}.{suffix}"
        for key, suffix in {
            "manifest": "json",
            "dev": "jsonl",
            "test": "jsonl",
            "profiles": "json",
            "errors": "json",
            "report": "json",
        }.items()
    }


def _cleanup(paths: dict[str, Path]) -> None:
    for path in paths.values():
        path.unlink(missing_ok=True)


def _manifest(path: Path) -> AblationBenchmarkManifest:
    manifest = AblationBenchmarkManifest(
        benchmark_version="agent-ablation-v1",
        dataset_hash=HASH,
        split_seed="safe-seed",
        sources=(
            SourceRevision(
                source_id="safe-source", status="verified",
                url="https://example.test/source", revision="a" * 40,
                license_spdx="MIT", attribution="Safe attribution",
                file_sha256="sha256:" + "b" * 64,
            ),
        ),
        splits=(
            AblationSplitManifest(
                split="calibration", sample_ids=("cal-1",), group_ids=("cal-g",),
                domain_counts={"benign_plain": 1}, family_counts={},
            ),
            AblationSplitManifest(
                split="dev", sample_ids=("dev-safe", "dev-risk"),
                group_ids=("dev-safe-g", "dev-risk-g"),
                domain_counts={"benign_plain": 1, "semantic_unsafe": 1},
                family_counts={},
            ),
            AblationSplitManifest(
                split="test",
                sample_ids=("test-safe", "test-risk", "test-failed"),
                group_ids=("test-safe-g", "test-risk-g", "test-failed-g"),
                domain_counts={
                    "benign_plain": 1,
                    "semantic_unsafe": 1,
                    "optimized_suffix": 1,
                },
                family_counts={"gcg": 1},
            ),
        ),
    )
    write_ascii_json(path, manifest)
    return manifest


def _observation(sample_id: str, split: str, risky: bool) -> AblationObservation:
    return AblationObservation(
        sample_id=sample_id,
        group_id=sample_id + "-g",
        split=split,
        domain="semantic_unsafe" if risky else "benign_plain",
        label_risky=risky,
        semantic_severity="unsafe" if risky else "safe",
        semantic_verification="performed",
        detector_score=0.9 if risky else 0.1,
        production_cpd_alarm=risky,
        semantic_latency_ms=1,
        total_latency_ms=2,
    )


def _write_observations(path: Path, rows: tuple[AblationObservation, ...]) -> None:
    path.write_text(
        "".join(
            json.dumps(row.model_dump(mode="json"), sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="ascii",
    )


def test_selector_reads_exact_dev_ids_and_writes_frozen_profiles() -> None:
    paths = _paths("ablation-cli-select")
    _manifest(paths["manifest"])
    _write_observations(
        paths["dev"],
        (
            _observation("dev-safe", "dev", False),
            _observation("dev-risk", "dev", True),
        ),
    )
    try:
        bundle = select_profiles(
            manifest_path=paths["manifest"],
            observations_path=paths["dev"],
            output_path=paths["profiles"],
        )
        serialized = paths["profiles"].read_text(encoding="ascii")
    finally:
        _cleanup(paths)

    assert len(bundle.profiles) == 9
    assert bundle.dataset_hash == HASH
    assert "dev-safe" not in serialized
    assert "sample_id" not in serialized


def test_selector_rejects_test_rows_and_evaluator_rejects_dev_rows() -> None:
    paths = _paths("ablation-cli-splits")
    _manifest(paths["manifest"])
    _write_observations(paths["dev"], (_observation("test-safe", "test", False),))
    try:
        with pytest.raises(ValueError, match="dev observation IDs"):
            select_profiles(
                manifest_path=paths["manifest"], observations_path=paths["dev"],
                output_path=paths["profiles"],
            )

        _write_observations(
            paths["dev"],
            (_observation("dev-safe", "dev", False), _observation("dev-risk", "dev", True)),
        )
        select_profiles(
            manifest_path=paths["manifest"], observations_path=paths["dev"],
            output_path=paths["profiles"],
        )
        paths["errors"].write_text("[]\n", encoding="ascii")
        with pytest.raises(ValueError, match="test observation IDs"):
            evaluate_test(
                manifest_path=paths["manifest"], profiles_path=paths["profiles"],
                observations_path=paths["dev"], errors_path=paths["errors"],
                output_path=paths["report"],
            )
    finally:
        _cleanup(paths)


def test_evaluator_accounts_for_failures_without_serializing_sample_ids() -> None:
    paths = _paths("ablation-cli-evaluate")
    _manifest(paths["manifest"])
    _write_observations(
        paths["dev"],
        (_observation("dev-safe", "dev", False), _observation("dev-risk", "dev", True)),
    )
    _write_observations(
        paths["test"],
        (_observation("test-safe", "test", False), _observation("test-risk", "test", True)),
    )
    paths["errors"].write_text(
        json.dumps([{"sample_id": "test-failed", "error_type": "TimeoutError"}]) + "\n",
        encoding="ascii",
    )
    try:
        select_profiles(
            manifest_path=paths["manifest"], observations_path=paths["dev"],
            output_path=paths["profiles"],
        )
        report = evaluate_test(
            manifest_path=paths["manifest"], profiles_path=paths["profiles"],
            observations_path=paths["test"], errors_path=paths["errors"],
            output_path=paths["report"],
        )
        serialized = paths["report"].read_text(encoding="ascii")
    finally:
        _cleanup(paths)

    assert report.requested_count == 3
    assert report.completed_count == 2
    assert report.failed_count == 1
    assert report.failure_counts == {"timeouterror": 1}
    assert "test-safe" not in serialized
    assert "test-failed" not in serialized
    assert "sample_id" not in serialized


def test_evaluator_rejects_unknown_or_missing_test_ids() -> None:
    paths = _paths("ablation-cli-identity")
    _manifest(paths["manifest"])
    _write_observations(
        paths["dev"],
        (_observation("dev-safe", "dev", False), _observation("dev-risk", "dev", True)),
    )
    _write_observations(paths["test"], (_observation("unknown", "test", False),))
    paths["errors"].write_text("[]\n", encoding="ascii")
    try:
        select_profiles(
            manifest_path=paths["manifest"], observations_path=paths["dev"],
            output_path=paths["profiles"],
        )
        with pytest.raises(ValueError, match="test observation IDs"):
            evaluate_test(
                manifest_path=paths["manifest"], profiles_path=paths["profiles"],
                observations_path=paths["test"], errors_path=paths["errors"],
                output_path=paths["report"],
            )
    finally:
        _cleanup(paths)
