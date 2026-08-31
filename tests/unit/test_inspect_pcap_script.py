from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest


WINDOWS_POWERSHELL = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "inspect_pcap.ps1"
PCAP_HEADER = bytes.fromhex("a1b2c3d4")


def _make_quarantine_capture(tmp_path: Path, suffix: str = ".pcap") -> tuple[Path, Path]:
    root = tmp_path / "quarantine"
    capture = root / "input" / f"capture{suffix}"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(PCAP_HEADER + b"test-fixture")
    return root, capture


def _valid_report(capture: Path) -> dict[str, object]:
    contents = capture.read_bytes()
    return {
        "schema_version": 1,
        "sha256": hashlib.sha256(contents).hexdigest(),
        "size_bytes": len(contents),
        "capture_format": "pcapng" if capture.suffix.lower() == ".pcapng" else "pcap",
        "packet_count": 0,
        "duration_seconds": 0.0,
        "link_types": [],
        "protocol_counts": {},
        "visibility": {
            "plaintext_application_protocol_observed": False,
            "encrypted_transport_observed": False,
            "tls_observed": False,
            "quic_observed": False,
        },
        "capability": "insufficient_evidence",
        "reasons": ["no_packets"],
        "tool_versions": {"tshark": "TShark 4.4.0"},
    }


def _write_fake_docker(
    tmp_path: Path,
    report: dict[str, object],
    exit_code: int = 0,
    *,
    write_private_stderr: bool = False,
) -> Path:
    fake = tmp_path / "fake-docker.cmd"
    argument_capture = tmp_path / "docker-args.txt"
    argument_capture.unlink(missing_ok=True)
    stderr = "echo PRIVATE_SENTINEL 1>&2\n" if write_private_stderr else ""
    fake.write_text(
        "@echo off\n"
        "setlocal DisableDelayedExpansion\n"
        "set \"ARGUMENT_CAPTURE=%~dp0docker-args.txt\"\n"
        ":arguments\n"
        "if \"%~1\"==\"\" goto output\n"
        ">>\"%ARGUMENT_CAPTURE%\" echo %~1\n"
        "shift\n"
        "goto arguments\n"
        ":output\n"
        f"echo {json.dumps(report)}\n"
        f"{stderr}"
        f"exit /b {exit_code}\n",
        encoding="utf-8",
    )
    return fake


def _run_launcher(path: Path, root: Path, fake_docker: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(WINDOWS_POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-Path",
            str(path),
            "-QuarantineRoot",
            str(root),
            "-DockerExecutable",
            str(fake_docker),
        ],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )


def test_launcher_uses_exact_sandbox_arguments(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    fake = _write_fake_docker(tmp_path, _valid_report(capture))

    result = _run_launcher(capture, root, fake)
    assert result.returncode == 0, result.stdout + result.stderr
    args = (tmp_path / "docker-args.txt").read_text(encoding="utf-8").splitlines()
    assert "--network" in args and args[args.index("--network") + 1] == "none"
    assert "--read-only" in args
    cap_index = args.index("--cap-drop")
    assert args[cap_index : cap_index + 2] == ["--cap-drop", "ALL"]
    assert "no-new-privileges=true" in args
    assert args[args.index("--cpus") + 1] == "1"
    assert args[args.index("--memory") + 1] == "512m"
    assert args[args.index("--pids-limit") + 1] == "64"
    mounts = [args[index + 1] for index, value in enumerate(args[:-1]) if value == "--mount"]
    assert len(mounts) == 1
    assert "target=/input/capture" in mounts[0]
    assert mounts[0].endswith(",readonly")


def test_launcher_rejects_path_outside_quarantine(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(PCAP_HEADER)

    result = _run_launcher(outside, root, tmp_path / "unused.cmd")

    assert result.returncode != 0
    assert "pcap_preflight_error=input_outside_quarantine" in result.stdout


def test_launcher_rejects_directory_input(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    directory = root / "input" / "capture.pcap"
    directory.mkdir(parents=True)

    result = _run_launcher(directory, root, tmp_path / "unused.cmd")

    assert result.returncode != 0
    assert "pcap_preflight_error=input_not_regular_file" in result.stdout


def test_launcher_rejects_extra_report_field(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_report(capture) | {"prompt": "PRIVATE_SENTINEL"}

    result = _run_launcher(capture, root, _write_fake_docker(tmp_path, report))

    assert result.returncode != 0
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr


def test_launcher_rejects_changed_post_run_hash(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_report(capture) | {"sha256": "0" * 64}

    result = _run_launcher(capture, root, _write_fake_docker(tmp_path, report))

    assert result.returncode != 0
    assert "pcap_preflight_error=input_changed" in result.stdout


def test_launcher_never_prints_private_docker_stderr(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    fake = _write_fake_docker(
        tmp_path, _valid_report(capture), exit_code=9, write_private_stderr=True
    )

    result = _run_launcher(capture, root, fake)

    assert result.returncode != 0
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr


@pytest.mark.parametrize("suffix", [".pcap", ".PCAP", ".pcapng", ".PCAPNG"])
def test_launcher_accepts_supported_extensions_case_insensitively(
    tmp_path: Path, suffix: str
) -> None:
    root, capture = _make_quarantine_capture(tmp_path, suffix)

    result = _run_launcher(capture, root, _write_fake_docker(tmp_path, _valid_report(capture)))

    assert result.returncode == 0, result.stdout + result.stderr


def test_launcher_writes_named_report_without_original_filename(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    renamed_capture = capture.with_name("operator-private-name.pcap")
    capture.rename(renamed_capture)
    report = _valid_report(renamed_capture)

    result = _run_launcher(
        renamed_capture, root, _write_fake_docker(tmp_path, report)
    )
    output = root / "output" / f"pcap-preflight-{report['sha256'][:16]}.json"

    assert result.returncode == 0, result.stdout + result.stderr
    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert renamed_capture.name not in output.name
    assert renamed_capture.name not in output.read_text(encoding="utf-8")
    assert list((root / "output").glob("pcap-preflight-*.json")) == [output]


def test_launcher_rejects_reparse_point_input_when_symlinks_are_available(
    tmp_path: Path,
) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    link = capture.with_name("linked.pcap")
    try:
        os.symlink(capture, link)
    except OSError:
        pytest.skip("symlink creation is unavailable for this Windows test user")

    result = _run_launcher(link, root, tmp_path / "unused.cmd")

    assert result.returncode != 0
    assert "pcap_preflight_error=input_reparse_point" in result.stdout


def test_launcher_runs_under_windows_powershell_5_1(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)

    result = _run_launcher(capture, root, _write_fake_docker(tmp_path, _valid_report(capture)))

    assert result.returncode == 0, result.stdout + result.stderr
