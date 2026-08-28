from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import app.evaluation.grounded_report as grounded_report


DATA = Path("data")
CONFIG = DATA / "report-generation-config-v2.json"
DEVELOPMENT = DATA / "report-generation-development-report-v2.json"
TEST = DATA / "report-generation-test-report-v2.json"
CORRECTION = DATA / "report-generation-correction-v2.json"


def _copy_historical_artifacts(root: Path, *, correction: bool) -> tuple[Path, Path, Path]:
    root.mkdir()
    config = root / CONFIG.name
    development = root / DEVELOPMENT.name
    test = root / TEST.name
    for source, destination in (
        (CONFIG, config),
        (DEVELOPMENT, development),
        (TEST, test),
    ):
        shutil.copyfile(source, destination)
    if correction:
        shutil.copyfile(CORRECTION, root / CORRECTION.name)
    return config, development, test


def _load_effective_summary(
    config: Path = CONFIG,
    development: Path = DEVELOPMENT,
    test: Path = TEST,
):
    return grounded_report.load_effective_report_summary(
        selected_config_path=config,
        development_report_path=development,
        test_report_path=test,
    )


def test_effective_summary_auto_discovers_correction_and_invalidates_legacy_pass() -> None:
    summary = _load_effective_summary()

    assert summary.raw_artifact_status == "historical_only_superseded"
    assert summary.source_artifacts_verified is True
    assert summary.action_invariance_evidence == "legacy_unverified"
    assert summary.target_status.action_invariance is False


def test_effective_summary_fails_closed_without_adjacent_correction(
    tmp_path: Path,
) -> None:
    config, development, test = _copy_historical_artifacts(
        tmp_path / "artifacts",
        correction=False,
    )

    with pytest.raises(FileNotFoundError, match="correction artifact is required"):
        _load_effective_summary(config, development, test)


def test_effective_summary_fails_closed_when_bound_artifact_changes(
    tmp_path: Path,
) -> None:
    config, development, test = _copy_historical_artifacts(
        tmp_path / "artifacts",
        correction=True,
    )
    test.write_bytes(test.read_bytes() + b" ")

    with pytest.raises(ValueError, match="artifact hash mismatch"):
        _load_effective_summary(config, development, test)


def test_official_summary_cli_defaults_to_effective_private_output() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/summarize_grounded_reports.py"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["raw_artifact_status"] == "historical_only_superseded"
    assert payload["action_invariance_evidence"] == "legacy_unverified"
    assert payload["target_status"]["action_invariance"] is False
    assert '"action_invariance":true' not in result.stdout
    forbidden = {
        "prompt",
        "suffix",
        "token",
        "token_text",
        "sample_id",
        "sample_ids",
        "raw_output",
        "raw_model_output",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return {str(key).casefold() for key in value} | {
                key for item in value.values() for key in keys(item)
            }
        if isinstance(value, list):
            return {key for item in value for key in keys(item)}
        return set()

    assert keys(payload).isdisjoint(forbidden)


def test_official_summary_cli_fails_closed_without_correction(
    tmp_path: Path,
) -> None:
    config, development, test = _copy_historical_artifacts(
        tmp_path / "artifacts",
        correction=False,
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/summarize_grounded_reports.py",
            "--selected-config",
            str(config),
            "--development-report",
            str(development),
            "--test-report",
            str(test),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert "correction artifact is required" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_official_summary_cli_does_not_reflect_tampered_private_values(
    tmp_path: Path,
) -> None:
    config, development, test = _copy_historical_artifacts(
        tmp_path / "artifacts",
        correction=True,
    )
    payload = json.loads(test.read_text(encoding="ascii"))
    payload["prompt"] = "PRIVATE_PROMPT_MUST_NOT_LEAK"
    test.write_text(json.dumps(payload), encoding="ascii")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/summarize_grounded_reports.py",
            "--selected-config",
            str(config),
            "--development-report",
            str(development),
            "--test-report",
            str(test),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert "effective report validation failed" in result.stderr
    assert "PRIVATE_PROMPT_MUST_NOT_LEAK" not in result.stderr
    assert str(tmp_path) not in result.stderr
