from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_lab_privacy.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


def _run(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    if POWERSHELL is None:
        pytest.skip("PowerShell is unavailable")
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            *arguments,
        ],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_privacy_verifier_accepts_safe_redacted_json(tmp_path: Path) -> None:
    fixture = tmp_path / "safe.json"
    fixture.write_text(
        json.dumps({"run_id": "lab_1", "signals": [{"index": 0, "risk": 0.1}]}),
        encoding="utf-8",
    )

    result = _run("-JsonPath", str(fixture), "-SkipTrackedPathScan")

    assert result.returncode == 0, result.stderr
    assert "privacy_verification=passed" in result.stdout
    assert "forbidden_key_hits=0" in result.stdout


def test_privacy_verifier_reports_nested_key_path_without_value(tmp_path: Path) -> None:
    fixture = tmp_path / "unsafe.json"
    private_value = "DO_NOT_PRINT_PRIVATE_VALUE"
    fixture.write_text(
        json.dumps({"outer": [{"token_text": private_value}]}),
        encoding="utf-8",
    )

    result = _run("-JsonPath", str(fixture), "-SkipTrackedPathScan")

    assert result.returncode != 0
    assert "forbidden-key:$.outer[0].token_text" in result.stdout
    assert private_value not in result.stdout
    assert private_value not in result.stderr


def test_privacy_verifier_rejects_tracked_protected_artifact_paths(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    protected = {
        ".secrets/key.txt": "PRIVATE_KEY_VALUE",
        "tmp/runtime.sqlite3": "PRIVATE_DATABASE_VALUE",
        "data/source-prompts.jsonl": "PRIVATE_PROMPT_VALUE",
        "tmp/observation-cache.json": "PRIVATE_OBSERVATION_VALUE",
    }
    for relative, value in protected.items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)

    result = _run("-RepositoryRoot", str(repository), cwd=repository)

    assert result.returncode != 0
    for relative, value in protected.items():
        assert f"tracked-path:{relative}" in result.stdout
        assert value not in result.stdout
        assert value not in result.stderr
