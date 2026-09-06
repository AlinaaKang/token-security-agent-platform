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
    stderr_text: str | None = None,
) -> Path:
    fake = tmp_path / "fake-docker.cmd"
    argument_capture = tmp_path / "docker-args.txt"
    argument_capture.unlink(missing_ok=True)
    stderr_value = stderr_text or ("PRIVATE_SENTINEL" if write_private_stderr else "")
    stderr = f"echo {stderr_value} 1>&2\n" if stderr_value else ""
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


def _run_launcher(
    path: Path, root: Path, fake_docker: Path, *, mode: str | None = None
) -> subprocess.CompletedProcess[str]:
    arguments = [
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
        ]
    if mode is not None:
        arguments.extend(["-Mode", mode])
    return subprocess.run(
        arguments,
        capture_output=True,
        check=False,
        encoding="utf-8",
    )


def _valid_detection_report() -> dict[str, object]:
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


def _make_directory_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        [os.environ["ComSpec"], "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    if result.returncode != 0:
        pytest.skip("directory junction creation is unavailable for this Windows test user")


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


def test_http_detection_maps_capture_error_without_leaking_private_stderr(
    tmp_path: Path,
) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    fake = _write_fake_docker(
        tmp_path,
        _valid_detection_report(),
        exit_code=2,
        stderr_text="pcap_detection_error=capture_invalid PRIVATE_SENTINEL",
    )

    result = _run_launcher(capture, root, fake, mode="HttpDetection")

    assert result.returncode != 0
    assert "pcap_preflight_error=capture_invalid" in result.stdout
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


def test_launcher_rejects_junction_input_root(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    root.mkdir()
    outside = tmp_path / "outside-input"
    outside.mkdir()
    capture = outside / "capture.pcap"
    capture.write_bytes(PCAP_HEADER)
    junction = root / "input"
    _make_directory_junction(junction, outside)

    try:
        result = _run_launcher(path=junction / capture.name, root=root, fake_docker=tmp_path / "unused.cmd")
    finally:
        junction.rmdir()

    assert result.returncode != 0
    assert "pcap_preflight_error=input_reparse_point" in result.stdout


def test_launcher_rejects_junction_in_input_path(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    input_root = root / "input"
    input_root.mkdir(parents=True)
    outside = tmp_path / "outside-nested"
    outside.mkdir()
    capture = outside / "capture.pcap"
    capture.write_bytes(PCAP_HEADER)
    junction = input_root / "nested"
    _make_directory_junction(junction, outside)

    try:
        result = _run_launcher(path=junction / capture.name, root=root, fake_docker=tmp_path / "unused.cmd")
    finally:
        junction.rmdir()

    assert result.returncode != 0
    assert "pcap_preflight_error=input_reparse_point" in result.stdout


def test_launcher_rejects_junction_output_directory(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    outside = tmp_path / "outside-output"
    outside.mkdir()
    junction = root / "output"
    _make_directory_junction(junction, outside)

    try:
        result = _run_launcher(capture, root, _write_fake_docker(tmp_path, _valid_report(capture)))
    finally:
        junction.rmdir()

    assert result.returncode != 0
    assert "pcap_preflight_error=output_reparse_point" in result.stdout
    assert list(outside.iterdir()) == []


def test_launcher_runs_under_windows_powershell_5_1(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)

    result = _run_launcher(capture, root, _write_fake_docker(tmp_path, _valid_report(capture)))

    assert result.returncode == 0, result.stdout + result.stderr


def test_http_detection_mode_dispatches_inside_the_same_sandbox(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_detection_report()

    result = _run_launcher(
        capture,
        root,
        _write_fake_docker(tmp_path, report),
        mode="HttpDetection",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = (tmp_path / "docker-args.txt").read_text(encoding="utf-8").splitlines()
    assert args[-2:] == ["token-security-pcap-preflight:local", "detect-http"]
    output_files = list((root / "output").glob("pcap-detection-*.json"))
    assert len(output_files) == 1
    assert json.loads(output_files[0].read_text(encoding="utf-8")) == report
    assert json.loads(result.stdout) == report


def test_http_detection_accepts_authorized_upload_capture(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    capture = root / "uploads" / "upload_0123456789abcdef.pcap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(PCAP_HEADER)
    report = _valid_detection_report()

    result = _run_launcher(
        capture,
        root,
        _write_fake_docker(tmp_path, report),
        mode="HttpDetection",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == report


def test_preflight_rejects_upload_capture(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    capture = root / "uploads" / "upload_0123456789abcdef.pcap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(PCAP_HEADER)

    result = _run_launcher(capture, root, tmp_path / "unused.cmd")

    assert result.returncode != 0
    assert "pcap_preflight_error=input_outside_quarantine" in result.stdout


def test_http_detection_accepts_current_request_evidence_contract(
    tmp_path: Path,
) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_detection_report()
    evidence = report["evidence"][0]  # type: ignore[index]
    evidence.update(  # type: ignore[union-attr]
        {
            "attack_candidate": "web_injection",
            "supporting_signals": ["xss_pattern", "request_boundary"],
            "purpose_candidates": ["internal_access"],
        }
    )

    result = _run_launcher(
        capture,
        root,
        _write_fake_docker(tmp_path, report),
        mode="HttpDetection",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == report


def test_http_detection_accepts_current_behavior_evidence_contract(
    tmp_path: Path,
) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_detection_report()
    evidence = report["evidence"][0]  # type: ignore[index]
    evidence.update(  # type: ignore[union-attr]
        {
            "granularity": "packet",
            "start_packet": 1,
            "end_packet": 3,
            "start_offset_ms": 0,
            "end_offset_ms": 250,
            "attack_candidate": "none",
            "detector": "behavior_anomaly",
            "confidence": 0.82,
            "supporting_signals": [
                "connection_rate_increase",
                "destination_density_increase",
            ],
        }
    )

    result = _run_launcher(
        capture,
        root,
        _write_fake_docker(tmp_path, report),
        mode="HttpDetection",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == report


@pytest.mark.parametrize(
    ("nested_path", "private_key"),
    [
        ((), "payload"),
        (("evidence", 0), "uri"),
        (("evidence", 0), "Prompt"),
        (("evidence", 0), "ip_address"),
    ],
)
def test_http_detection_mode_rejects_private_report_fields(
    tmp_path: Path, nested_path: tuple[str | int, ...], private_key: str
) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_detection_report()
    target = report
    for segment in nested_path:
        target = target[segment]  # type: ignore[assignment,index]
    target[private_key] = "PRIVATE_SENTINEL"

    result = _run_launcher(
        capture,
        root,
        _write_fake_docker(tmp_path, report),
        mode="HttpDetection",
    )

    assert result.returncode != 0
    assert "pcap_preflight_error=invalid_report_schema" in result.stdout
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr
