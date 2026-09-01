from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path
from typing import Any

from app.pcap.config import PcapConfig
from app.pcap.models import PcapBatchSummary, PcapOverview


_BATCH_ID = re.compile(r"^batch_[0-9a-f]{32}$")
_MAX_FILES = 20
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ADD_FILE = 0x0002
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_LIST_DIRECTORY = 0x0001
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_NON_DIRECTORY_FILE = 0x0040
_FILE_CREATE = 2
_FILE_OPEN_REPARSE_POINT = 0x00200000
_FILE_SHARE_ALL = 0x00000007
_FILE_SYNCHRONOUS_IO_NONALERT = 0x0020
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_STATUS_OBJECT_NAME_COLLISION = ctypes.c_long(0xC0000035).value
_SYNCHRONIZE = 0x00100000


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("maximum_length", ctypes.c_ushort),
        ("buffer", ctypes.c_wchar_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root_directory", wintypes.HANDLE),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("status", wintypes.LONG), ("information", ctypes.c_size_t)]


class PcapToolFailed(RuntimeError):
    def __init__(self) -> None:
        super().__init__("pcap_batch_failed")


class PcapBatchExecutor:
    def __init__(
        self,
        *,
        config: PcapConfig,
        runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        self._config = config
        self._runner = runner

    def overview(self) -> PcapOverview:
        return PcapOverview(enabled=True)

    def execute(self, batch_id: str, max_files: int) -> PcapBatchSummary:
        _validate_batch_id(batch_id)
        _validate_max_files(max_files)
        command = self._command(batch_id, max_files)
        try:
            completed = self._runner(
                command,
                capture_output=True,
                check=False,
                encoding="utf-8",
                shell=False,
                timeout=max_files * 160 + 30,
            )
            if (
                completed.returncode != 0
                or completed.stdout.strip() != f"pcap_batch_result={batch_id}"
            ):
                raise PcapToolFailed()
            return self._load_summary(batch_id)
        except PcapToolFailed:
            raise
        except Exception:
            raise PcapToolFailed() from None

    def request_cancel(self, batch_id: str) -> None:
        _validate_batch_id(batch_id)
        try:
            state_directory = self._config.quarantine_root / "state"
            _reject_reparse_point(state_directory)
            state_directory.mkdir(parents=True, exist_ok=True)
            _reject_reparse_point(state_directory)
            expected_state = self._config.quarantine_root.resolve(strict=True) / "state"
            if state_directory.resolve(strict=True) != expected_state:
                raise ValueError("state directory must remain inside quarantine root")
            _create_cancel_marker(state_directory, f"{batch_id}.cancel")
        except Exception:
            raise PcapToolFailed() from None

    def _command(self, batch_id: str, max_files: int) -> list[str]:
        return [
            str(self._config.powershell_executable),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self._config.batch_script),
            "-QuarantineRoot",
            str(self._config.quarantine_root),
            "-InspectorScript",
            str(self._config.inspect_script),
            "-BatchId",
            batch_id,
            "-MaxFiles",
            str(max_files),
        ]

    def _load_summary(self, batch_id: str) -> PcapBatchSummary:
        report_path = (
            self._config.quarantine_root / "output" / f"pcap-batch-{batch_id}.json"
        )
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        summary = PcapBatchSummary.model_validate(payload)
        if summary.batch_id != batch_id:
            raise PcapToolFailed()
        return summary


def _validate_batch_id(batch_id: str) -> None:
    if type(batch_id) is not str or _BATCH_ID.fullmatch(batch_id) is None:
        raise ValueError("batch_id must be a valid public batch identifier")


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 20")


def _reject_reparse_point(path: Path) -> None:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return
    if path.is_symlink() or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("PCAP state paths cannot be reparse points")


def _create_cancel_marker(state_directory: Path, marker_name: str) -> None:
    if os.name != "nt":
        raise OSError("PCAP cancellation requires Windows directory handles")

    directory_handle = _open_state_directory(state_directory)
    try:
        # Resolve the marker against the held directory handle, not a path string.
        marker_handle = _create_marker_relative_to(directory_handle, marker_name)
        try:
            _reject_handle_reparse_point(marker_handle)
        finally:
            _close_handle(marker_handle)
    finally:
        _close_handle(directory_handle)


def _open_state_directory(state_directory: Path) -> wintypes.HANDLE:
    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(state_directory),
        _FILE_LIST_DIRECTORY | _FILE_ADD_FILE | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_ALL,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("could not open PCAP state directory")
    typed_handle = wintypes.HANDLE(handle)
    try:
        _reject_handle_reparse_point(typed_handle)
    except Exception:
        _close_handle(typed_handle)
        raise
    return typed_handle


def _create_marker_relative_to(
    directory_handle: wintypes.HANDLE, marker_name: str
) -> wintypes.HANDLE:
    buffer = ctypes.create_unicode_buffer(marker_name)
    name = _UnicodeString(
        length=len(marker_name) * ctypes.sizeof(ctypes.c_wchar),
        maximum_length=(len(marker_name) + 1) * ctypes.sizeof(ctypes.c_wchar),
        buffer=ctypes.cast(buffer, ctypes.c_wchar_p),
    )
    attributes = _ObjectAttributes(
        length=ctypes.sizeof(_ObjectAttributes),
        root_directory=directory_handle,
        object_name=ctypes.pointer(name),
        attributes=0,
        security_descriptor=None,
        security_quality_of_service=None,
    )
    status_block = _IoStatusBlock()
    marker_handle = wintypes.HANDLE()
    create_file = ctypes.windll.ntdll.NtCreateFile
    create_file.restype = wintypes.LONG
    status = create_file(
        ctypes.byref(marker_handle),
        _GENERIC_WRITE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        ctypes.byref(attributes),
        ctypes.byref(status_block),
        None,
        0,
        _FILE_SHARE_ALL,
        _FILE_CREATE,
        _FILE_NON_DIRECTORY_FILE | _FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0,
    )
    if status == _STATUS_OBJECT_NAME_COLLISION:
        status = create_file(
            ctypes.byref(marker_handle),
            _GENERIC_WRITE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(status_block),
            None,
            0,
            _FILE_SHARE_ALL,
            _OPEN_EXISTING,
            _FILE_NON_DIRECTORY_FILE
            | _FILE_SYNCHRONOUS_IO_NONALERT
            | _FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )
    if status != 0:
        raise OSError("could not create PCAP cancellation marker")
    return marker_handle


def _reject_handle_reparse_point(handle: wintypes.HANDLE) -> None:
    information = _ByHandleFileInformation()
    if not ctypes.windll.kernel32.GetFileInformationByHandle(
        handle, ctypes.byref(information)
    ):
        raise OSError("could not inspect PCAP state path")
    if information.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("PCAP state paths cannot be reparse points")


def _close_handle(handle: wintypes.HANDLE) -> None:
    if not ctypes.windll.kernel32.CloseHandle(handle):
        raise OSError("could not close PCAP state handle")


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("creation_time", ctypes.c_byte * 8),
        ("last_access_time", ctypes.c_byte * 8),
        ("last_write_time", ctypes.c_byte * 8),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]
