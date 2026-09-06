from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.pcap.detection_executor as detection_executor_module
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


@pytest.mark.parametrize(
    ("returncode", "stdout", "expected_failure"),
    [
        (2, "pcap_preflight_error=capture_invalid", "capture_invalid"),
        (2, "pcap_preflight_error=docker_timeout", "tool_timeout"),
        (0, "not-json", "report_invalid"),
    ],
)
def test_detection_executor_reports_public_failure_categories(
    tmp_path: Path,
    returncode: int,
    stdout: str,
    expected_failure: str,
) -> None:
    config = _config(tmp_path)
    (config.quarantine_root / "input" / "capture.pcap").write_bytes(b"capture")

    def runner(_command: list[str], **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=returncode,
            stdout=stdout,
            stderr="PRIVATE_PATH_AND_PAYLOAD",
        )

    summary = PcapDetectionExecutor(config=config, runner=runner).execute(
        "detection_0123456789abcdef0123456789abcdef", max_files=1
    )

    assert summary.processed_samples[0].failure_code == expected_failure
    assert "PRIVATE" not in summary.model_dump_json()


def test_detection_executor_publishes_each_processed_sample_incrementally(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    (config.quarantine_root / "input" / "first.pcap").write_bytes(b"pcap-one")
    (config.quarantine_root / "input" / "second.pcap").write_bytes(b"pcap-two")

    def runner(_command: list[str], **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout=json.dumps({**_detection_report(), "evidence": []}), stderr="")

    progress: list[int] = []
    summary = PcapDetectionExecutor(config=config, runner=runner).execute(
        "detection_0123456789abcdef0123456789abcdef",
        max_files=2,
        on_progress=lambda snapshot: progress.append(len(snapshot.processed_samples)),
    )

    assert progress == [1, 2]
    assert len(summary.processed_samples) == 2


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


def test_detection_executor_inspects_exactly_one_uploaded_capture_without_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    uploads = config.quarantine_root / "uploads"
    uploads.mkdir()
    capture = uploads / "upload_private.pcap"
    capture.write_bytes(bytes.fromhex("a1b2c3d4") + bytes(20))
    commands: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({**_detection_report(), "evidence": []}),
            stderr="",
        )

    def forbid_discovery(*_args: object, **_kwargs: object) -> tuple[Path, ...]:
        raise AssertionError("uploaded detection must not discover directory captures")

    monkeypatch.setattr(detection_executor_module, "_capture_paths", forbid_discovery)
    progress: list[int] = []

    summary = PcapDetectionExecutor(config=config, runner=runner).execute_capture(
        "detection_0123456789abcdef0123456789abcdef",
        capture,
        on_progress=lambda current: progress.append(current.analyzed_count),
    )

    assert summary.analyzed_count == 1
    assert summary.processed_samples[0].sample_index == 1
    assert progress == [1]
    assert len(commands) == 1
    assert commands[0][commands[0].index("-Path") + 1] == str(capture)


@pytest.mark.parametrize("location", ["outside", "directory"])
def test_detection_executor_rejects_uploaded_paths_outside_owned_regular_files(
    tmp_path: Path, location: str
) -> None:
    config = _config(tmp_path)
    uploads = config.quarantine_root / "uploads"
    uploads.mkdir()
    capture = tmp_path / "outside.pcap" if location == "outside" else uploads / "folder"
    if location == "outside":
        capture.write_bytes(b"capture")
    else:
        capture.mkdir()

    with pytest.raises(PcapDetectionToolFailed):
        PcapDetectionExecutor(config=config).execute_capture(
            "detection_0123456789abcdef0123456789abcdef", capture
        )
