from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest

from app.pcap.config import PcapConfig
from app.pcap.executor import PcapBatchExecutor, PcapToolFailed


def batch_id() -> str:
    return "batch_" + "a" * 32


def public_summary_payload(*, identifier: str = batch_id()) -> dict[str, object]:
    return {
        "schema_version": 1,
        "batch_id": identifier,
        "selected_count": 1,
        "succeeded_count": 1,
        "failed_count": 0,
        "skipped_count": 0,
        "captures": [
            {
                "capture_id": "capture_" + "b" * 32,
                "status": "succeeded",
                "packet_count": 4,
                "protocol_counts": {"dns": 1, "tls": 3},
                "visibility": {
                    "plaintext_application_protocol_observed": False,
                    "encrypted_transport_observed": True,
                    "tls_observed": True,
                    "quic_observed": False,
                },
                "capability": "traffic_only",
                "error_code": None,
            }
        ],
    }


def config_fixture(tmp_path: Path) -> PcapConfig:
    root = tmp_path / "quarantine"
    (root / "input").mkdir(parents=True)
    powershell = tmp_path / "powershell.exe"
    batch_script = tmp_path / "inspect_pcap_batch.ps1"
    inspect_script = tmp_path / "inspect_pcap.ps1"
    for file in (powershell, batch_script, inspect_script):
        file.touch()
    return PcapConfig(
        quarantine_root=root,
        powershell_executable=powershell,
        batch_script=batch_script,
        inspect_script=inspect_script,
    )


class RecordingRunner:
    def __init__(
        self, *, returncode: int = 0, stdout: str = "", stderr: str = ""
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.command: list[str] | None = None
        self.kwargs: dict[str, Any] | None = None

    def __call__(self, command: list[str], **kwargs: Any) -> RecordingRunner:
        self.command = command
        self.kwargs = kwargs
        return self


def write_public_summary(root: Path, payload: dict[str, object]) -> None:
    output = root / "output"
    output.mkdir(exist_ok=True)
    identifier = str(payload["batch_id"])
    (output / f"pcap-batch-{identifier}.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def test_executor_uses_only_configured_paths_and_fixed_arguments(tmp_path: Path) -> None:
    config = config_fixture(tmp_path)
    write_public_summary(config.quarantine_root, public_summary_payload())
    runner = RecordingRunner(stdout="pcap_batch_result=" + batch_id())
    executor = PcapBatchExecutor(config=config, runner=runner)

    summary = executor.execute(batch_id(), 20)

    assert tuple(inspect.signature(executor.execute).parameters) == (
        "batch_id",
        "max_files",
    )
    assert runner.command is not None
    assert runner.command[0] == str(config.powershell_executable)
    assert runner.command[1:5] == [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
    ]
    assert runner.command == [
        str(config.powershell_executable),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(config.batch_script),
        "-QuarantineRoot",
        str(config.quarantine_root),
        "-InspectorScript",
        str(config.inspect_script),
        "-BatchId",
        batch_id(),
        "-MaxFiles",
        "20",
    ]
    assert runner.kwargs == {
        "capture_output": True,
        "check": False,
        "encoding": "utf-8",
        "shell": False,
        "timeout": 3230,
    }
    assert summary.selected_count == 1


def test_executor_never_reflects_raw_stderr(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=2, stdout="", stderr="PRIVATE_SENTINEL")

    with pytest.raises(PcapToolFailed, match="pcap_batch_failed") as failure:
        PcapBatchExecutor(config=config_fixture(tmp_path), runner=runner).execute(
            batch_id(), 1
        )

    assert "PRIVATE_SENTINEL" not in str(failure.value)


@pytest.mark.parametrize(
    "stdout",
    ["", "pcap_batch_result=" + batch_id() + "\nunexpected", "pcap_batch_error=bad"],
)
def test_executor_rejects_malformed_process_output(tmp_path: Path, stdout: str) -> None:
    config = config_fixture(tmp_path)
    write_public_summary(config.quarantine_root, public_summary_payload())

    with pytest.raises(PcapToolFailed, match="pcap_batch_failed"):
        PcapBatchExecutor(config=config, runner=RecordingRunner(stdout=stdout)).execute(
            batch_id(), 1
        )


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {"batch_id": batch_id()},
        public_summary_payload(identifier="batch_" + "c" * 32),
        public_summary_payload() | {"path": "PRIVATE_SENTINEL"},
    ],
)
def test_executor_rejects_missing_malformed_mismatched_or_private_reports(
    tmp_path: Path, payload: dict[str, object] | None
) -> None:
    config = config_fixture(tmp_path)
    if payload is not None:
        write_public_summary(config.quarantine_root, payload)

    with pytest.raises(PcapToolFailed, match="pcap_batch_failed") as failure:
        PcapBatchExecutor(
            config=config, runner=RecordingRunner(stdout="pcap_batch_result=" + batch_id())
        ).execute(batch_id(), 1)

    assert "PRIVATE_SENTINEL" not in str(failure.value)


def test_executor_creates_cancellation_marker_only_inside_configured_state(
    tmp_path: Path,
) -> None:
    config = config_fixture(tmp_path)
    executor = PcapBatchExecutor(config=config, runner=RecordingRunner())

    executor.request_cancel(batch_id())

    assert (config.quarantine_root / "state" / f"{batch_id()}.cancel").is_file()
    assert not list(tmp_path.glob("*.cancel"))


def test_executor_rejects_a_reparse_point_for_the_configured_state_directory(
    tmp_path: Path,
) -> None:
    config = config_fixture(tmp_path)
    outside = tmp_path / "outside-state"
    outside.mkdir()
    state = config.quarantine_root / "state"
    result = subprocess.run(
        [os.environ["ComSpec"], "/d", "/c", "mklink", "/J", str(state), str(outside)],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    if result.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        with pytest.raises(PcapToolFailed, match="pcap_batch_failed"):
            PcapBatchExecutor(config=config, runner=RecordingRunner()).request_cancel(
                batch_id()
            )
    finally:
        state.rmdir()

    assert not (outside / f"{batch_id()}.cancel").exists()


def test_overview_does_not_open_capture_contents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = config_fixture(tmp_path)
    (config.quarantine_root / "input" / "placeholder.pcap").write_bytes(b"not a pcap")

    def forbidden(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("overview opened capture content")

    monkeypatch.setattr(Path, "read_bytes", forbidden)

    overview = PcapBatchExecutor(config=config, runner=RecordingRunner()).overview()

    assert overview.enabled is True
    assert overview.max_batch_size == 20
