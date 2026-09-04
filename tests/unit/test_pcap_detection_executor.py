from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.pcap.config import PcapConfig
from app.pcap.detection_executor import PcapDetectionExecutor, PcapDetectionToolFailed


def _config(tmp_path: Path) -> PcapConfig:
    root = tmp_path / "quarantine"
    (root / "input").mkdir(parents=True)
    powershell = tmp_path / "powershell.exe"
    batch = tmp_path / "batch.ps1"
    inspect = tmp_path / "inspect.ps1"
    recon = tmp_path / "recon.ps1"
    for path in (powershell, batch, inspect, recon):
        path.write_text("fixture", encoding="utf-8")
    return PcapConfig(
        quarantine_root=root,
        powershell_executable=powershell,
        batch_script=batch,
        inspect_script=inspect,
        recon_batch_script=recon,
    )


def _detection_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "verified_packet_count": 3,
        "evidence": [
            {
                "evidence_id": "evidence_0123456789abcdef0123456789abcdef",
                "granularity": "request",
                "verified_packet_count": 3,
                "start_packet": 2,
                "end_packet": 2,
                "start_offset_ms": 100,
                "end_offset_ms": 100,
                "attack_candidate": "sql_injection",
                "detector": "http_rule",
                "confidence": 0.95,
                "supporting_signals": ["sql_syntax_pattern", "request_boundary"],
            }
        ],
    }


def test_detection_executor_preserves_valid_evidence_across_partial_failure(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    (config.quarantine_root / "input" / "first.pcap").write_bytes(b"pcap-one")
    (config.quarantine_root / "input" / "second.pcapng").write_bytes(b"pcap-two")
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        if len(calls) == 1:
            return SimpleNamespace(
                returncode=0, stdout=json.dumps(_detection_report()), stderr=""
            )
        return SimpleNamespace(
            returncode=2,
            stdout="pcap_preflight_error=docker_failed",
            stderr="PRIVATE_PATH_AND_PAYLOAD",
        )

    executor = PcapDetectionExecutor(config=config, runner=runner)
    summary = executor.execute(
        "detection_0123456789abcdef0123456789abcdef", max_files=2
    )

    assert summary.analyzed_count == 2
    assert summary.succeeded_count == 1
    assert summary.failed_count == 1
    assert len(summary.evidence) == 1
    assert summary.evidence[0].start_packet == 2
    assert all("-Mode" in command for command in calls)
    assert all(command[command.index("-Mode") + 1] == "HttpDetection" for command in calls)
    assert "PRIVATE" not in summary.model_dump_json()


def test_detection_executor_overview_counts_only_regular_capture_files(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    (config.quarantine_root / "input" / "one.pcap").write_bytes(b"one")
    (config.quarantine_root / "input" / "ignore.txt").write_text("ignore")

    overview = PcapDetectionExecutor(config=config).overview()

    assert overview.enabled is True
    assert overview.eligible_file_count == 1
    assert overview.max_files == 20


def test_detection_executor_fails_closed_on_oversized_public_output(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    (config.quarantine_root / "input" / "one.pcap").write_bytes(b"one")

    def runner(_command: list[str], **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="x" * (256 * 1024 + 1), stderr="")

    summary = PcapDetectionExecutor(config=config, runner=runner).execute(
        "detection_0123456789abcdef0123456789abcdef", max_files=1
    )

    assert summary.succeeded_count == 0
    assert summary.failed_count == 1


@pytest.mark.parametrize(
    "detection_id",
    ["mission_" + "a" * 32, "detection_" + "A" * 32, "detection_short"],
)
def test_detection_executor_rejects_invalid_public_identifiers(
    tmp_path: Path, detection_id: str
) -> None:
    with pytest.raises(ValueError, match="detection_id"):
        PcapDetectionExecutor(config=_config(tmp_path)).execute(detection_id, 1)


def test_detection_executor_redacts_enumeration_failures(tmp_path: Path) -> None:
    config = _config(tmp_path)
    (config.quarantine_root / "input").rmdir()

    with pytest.raises(PcapDetectionToolFailed, match="pcap_detection_failed"):
        PcapDetectionExecutor(config=config).execute(
            "detection_0123456789abcdef0123456789abcdef", 1
        )
