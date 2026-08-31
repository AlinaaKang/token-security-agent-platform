from __future__ import annotations

import os
import subprocess
from pathlib import Path


WINDOWS_POWERSHELL = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_pcap_sandbox.ps1"


def test_verifier_suppresses_native_stderr_on_fixture_failure(tmp_path: Path) -> None:
    fake_python = tmp_path / "python.cmd"
    fake_python.write_text(
        "@echo off\n"
        "echo PRIVATE_SENTINEL 1>&2\n"
        "exit /b 9\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PATH"] = f"{tmp_path}{os.pathsep}{environment['PATH']}"

    result = subprocess.run(
        [
            str(WINDOWS_POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-DockerExecutable",
            str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"),
        ],
        capture_output=True,
        check=False,
        encoding="utf-8",
        env=environment,
    )

    assert result.returncode != 0
    assert "pcap_sandbox_verification=failed code=fixture_generation_failed" in result.stdout
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr
