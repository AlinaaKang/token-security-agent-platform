from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

import app.pcap.windows_handles as windows_handles


def test_executor_imports_when_msvcrt_is_unavailable() -> None:
    script = "import builtins\nreal=builtins.__import__\ndef blocked(name,*args,**kwargs):\n    if name == 'msvcrt': raise ModuleNotFoundError(name)\n    return real(name,*args,**kwargs)\nbuiltins.__import__=blocked\nimport app.pcap.windows_handles\n"
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root / "backend"), str(root)])
    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_relative_reader_preserves_crlf_bytes_for_cap_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    msvcrt = pytest.importorskip("msvcrt")
    report = tmp_path / "report.json"
    report.write_bytes((b"{\"x\":1}\r\n" * 40_000))
    fd = os.open(report, os.O_RDONLY)

    class Handle:
        value = fd

    monkeypatch.setattr(windows_handles, "_nt_create_relative", lambda *args: (Handle(), 0))
    monkeypatch.setattr(windows_handles, "_reject_handle_reparse_point", lambda *_: None)
    monkeypatch.setattr(msvcrt, "open_osfhandle", lambda *_: fd)
    monkeypatch.setattr(windows_handles, "_close_handle", lambda *_: None)
    with pytest.raises(ValueError, match="size limit"):
        windows_handles._read_file_relative(object(), "report.json")
