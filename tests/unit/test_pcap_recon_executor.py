from __future__ import annotations

import inspect
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from app.pcap.config import PcapConfig
from app.pcap.recon_executor import PcapReconExecutor, PcapReconToolFailed


def recon_id() -> str:
    return "recon_" + "a" * 32


def config_fixture(tmp_path: Path) -> PcapConfig:
    root = tmp_path / "quarantine"
    (root / "input").mkdir(parents=True)
    for name in ("powershell.exe", "batch.ps1", "inspect.ps1", "recon.ps1"):
        (tmp_path / name).touch()
    return PcapConfig(
        quarantine_root=root,
        powershell_executable=tmp_path / "powershell.exe",
        batch_script=tmp_path / "batch.ps1",
        inspect_script=tmp_path / "inspect.ps1",
        recon_batch_script=tmp_path / "recon.ps1",
    )


def summary_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "sampled_count": 1,
        "succeeded_count": 1,
        "failed_count": 0,
        "quartile_counts": {"quartile_1": 1, "quartile_2": 0, "quartile_3": 0, "quartile_4": 0},
        "size_bucket_counts": {"under_2_kib": 1, "2_kib_to_64_kib": 0, "64_kib_to_1_mib": 0, "at_least_1_mib": 0},
        "packet_bucket_counts": {"empty": 0, "1_to_15": 1, "16_to_63": 0, "at_least_64": 0},
        "duration_bucket_counts": {"zero": 0, "under_1_second": 1, "1_to_10_seconds": 0, "over_10_seconds": 0},
        "protocol_presence_counts": {"dns": 1},
        "plaintext_sample_count": 0,
        "encrypted_sample_count": 0,
        "sequence_candidate_count": 0,
    }


def write_summary(config: PcapConfig, payload: dict[str, object], identifier: str = recon_id()) -> None:
    output = config.quarantine_root / "output"
    output.mkdir(exist_ok=True)
    (output / f"pcap-recon-{identifier}.json").write_text(json.dumps(payload), encoding="utf-8")


class Runner:
    returncode = 0
    stdout = "pcap_recon_result=" + recon_id()
    stderr = ""

    def __init__(self) -> None:
        self.command: list[str] | None = None
        self.kwargs: dict[str, Any] | None = None

    def __call__(self, command: list[str], **kwargs: Any) -> Runner:
        self.command = command
        self.kwargs = kwargs
        return self


def test_recon_executor_uses_fixed_script_arguments_and_dynamic_overview(
    tmp_path: Path,
) -> None:
    config = config_fixture(tmp_path)
    (config.quarantine_root / "input" / "a.pcap").write_bytes(b"synthetic")
    runner = Runner()
    executor = PcapReconExecutor(config=config, runner=runner)

    overview = executor.overview()

    assert overview.model_dump(mode="json") == {
        "enabled": True,
        "eligible_file_count": 1,
        "sample_limit": 100,
        "sampling_method": "size_quartile_v1",
    }
    assert tuple(inspect.signature(executor.execute).parameters) == (
        "recon_id",
        "max_files",
    )


def test_recon_executor_executes_with_fixed_maximum_and_timeout(tmp_path: Path) -> None:
    config = config_fixture(tmp_path)
    write_summary(config, summary_payload())
    runner = Runner()
    executor = PcapReconExecutor(config=config, runner=runner)

    summary = executor.execute(recon_id())

    assert summary.sampled_count == 1
    assert runner.command == [
        str(config.powershell_executable), "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", str(config.recon_batch_script),
        "-QuarantineRoot", str(config.quarantine_root), "-InspectorScript",
        str(config.inspect_script), "-ReconId", recon_id(), "-StateId",
        executor.checkpoint_scope_id, "-MaxFiles", "100",
    ]
    assert runner.kwargs == {
        "capture_output": True, "check": False, "encoding": "utf-8",
        "shell": False, "timeout": 16030,
    }


def test_recon_executor_maps_runner_failures_without_reflecting_stderr(tmp_path: Path) -> None:
    runner = Runner()
    runner.returncode = 2
    runner.stderr = "PRIVATE_SENTINEL"
    with pytest.raises(PcapReconToolFailed, match="pcap_recon_failed") as failure:
        PcapReconExecutor(config=config_fixture(tmp_path), runner=runner).execute(recon_id())
    assert "PRIVATE_SENTINEL" not in str(failure.value)


@pytest.mark.parametrize("identifier", ["recon_" + "A" * 32, "recon_short", "batch_" + "a" * 32])
def test_recon_executor_rejects_non_recon_identifiers(tmp_path: Path, identifier: str) -> None:
    with pytest.raises(ValueError):
        PcapReconExecutor(config=config_fixture(tmp_path), runner=Runner()).execute(identifier)


def test_recon_executor_accepts_custom_sample_limit(tmp_path: Path) -> None:
    config = config_fixture(tmp_path)
    write_summary(config, summary_payload())
    runner = Runner()

    PcapReconExecutor(config=config, runner=runner).execute(recon_id(), 37)

    assert runner.command is not None
    assert runner.command[-1] == "37"


def test_recon_executor_rejects_oversized_sample_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        PcapReconExecutor(config=config_fixture(tmp_path), runner=Runner()).execute(recon_id(), 10001)


def test_recon_executor_rejects_summary_larger_than_authorized_scope(tmp_path: Path) -> None:
    config = config_fixture(tmp_path)
    payload = summary_payload()
    payload.update(
        sampled_count=2,
        succeeded_count=2,
        quartile_counts={"quartile_1": 2, "quartile_2": 0, "quartile_3": 0, "quartile_4": 0},
        size_bucket_counts={"under_2_kib": 2, "2_kib_to_64_kib": 0, "64_kib_to_1_mib": 0, "at_least_1_mib": 0},
        packet_bucket_counts={"empty": 0, "1_to_15": 2, "16_to_63": 0, "at_least_64": 0},
        duration_bucket_counts={"zero": 0, "under_1_second": 2, "1_to_10_seconds": 0, "over_10_seconds": 0},
        protocol_presence_counts={"dns": 2},
    )
    write_summary(config, payload)

    with pytest.raises(PcapReconToolFailed):
        PcapReconExecutor(config=config, runner=Runner()).execute(recon_id(), 1)


def test_recon_executor_maps_timeout_without_reflecting_exception(tmp_path: Path) -> None:
    class TimeoutRunner(Runner):
        def __call__(self, command: list[str], **kwargs: Any) -> Runner:
            raise subprocess.TimeoutExpired(command, 3230)

    with pytest.raises(PcapReconToolFailed, match="pcap_recon_failed"):
        PcapReconExecutor(config=config_fixture(tmp_path), runner=TimeoutRunner()).execute(recon_id())


@pytest.mark.parametrize(
    "update",
    [
        {"unexpected": "value"},
        {"quartile_counts": {"quartile_1": 0, "quartile_2": 0, "quartile_3": 0, "quartile_4": 0}},
    ],
)
def test_recon_executor_rejects_unknown_or_mismatched_output(
    tmp_path: Path, update: dict[str, object]
) -> None:
    config = config_fixture(tmp_path)
    write_summary(config, summary_payload() | update)
    with pytest.raises(PcapReconToolFailed):
        PcapReconExecutor(config=config, runner=Runner()).execute(recon_id())


def test_recon_executor_rejects_oversized_output_and_reparse_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = config_fixture(tmp_path)
    executor = PcapReconExecutor(config=config, runner=Runner())
    monkeypatch.setattr("app.pcap.recon_executor._open_quarantine_root", lambda _: object())
    monkeypatch.setattr("app.pcap.recon_executor._open_directory_relative", lambda *_: object())
    monkeypatch.setattr("app.pcap.recon_executor._close_handle", lambda *_: None)
    monkeypatch.setattr("app.pcap.recon_executor._read_file_relative", lambda *_: "{}" * 200_000)
    with pytest.raises(PcapReconToolFailed):
        executor.execute(recon_id())

    monkeypatch.setattr("app.pcap.recon_executor._open_directory_relative", lambda *_: (_ for _ in ()).throw(ValueError("reparse")))
    with pytest.raises(PcapReconToolFailed):
        executor.execute(recon_id())


def test_recon_executor_rejects_invalid_utf8(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = config_fixture(tmp_path)
    monkeypatch.setattr("app.pcap.recon_executor._open_quarantine_root", lambda _: object())
    monkeypatch.setattr("app.pcap.recon_executor._open_directory_relative", lambda *_: object())
    monkeypatch.setattr("app.pcap.recon_executor._close_handle", lambda *_: None)
    monkeypatch.setattr(
        "app.pcap.recon_executor._read_file_relative",
        lambda *_: (_ for _ in ()).throw(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")),
    )
    with pytest.raises(PcapReconToolFailed):
        PcapReconExecutor(config=config, runner=Runner()).execute(recon_id())
