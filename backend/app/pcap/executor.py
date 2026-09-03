from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.pcap.config import PcapConfig
from app.pcap.models import PcapBatchSummary, PcapOverview
from app.pcap.windows_handles import (
    _ByHandleFileInformation,
    _FILE_ATTRIBUTE_REPARSE_POINT,
    _close_handle,
    _create_marker_relative_to,
    _open_directory_relative,
    _open_or_create_directory_relative,
    _open_quarantine_root,
    _read_file_relative,
    _nt_create_relative,
    _verified_handle,
    _reject_handle_reparse_point,
)


_BATCH_ID = re.compile(r"^batch_[0-9a-f]{32}$")
_MAX_FILES = 20
_MAX_PENDING_FILE_COUNT = 2_147_483_647
_PCAP_EXTENSIONS = frozenset({".pcap", ".pcapng"})
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
        self._checkpoint_scope_id = _checkpoint_scope_id(config)

    @property
    def checkpoint_scope_id(self) -> str:
        return self._checkpoint_scope_id

    def overview(self) -> PcapOverview:
        try:
            pending_file_count = _count_pending_files(
                self._config.quarantine_root / "input"
            )
            return PcapOverview(
                enabled=True, pending_file_count=pending_file_count
            )
        except PcapToolFailed:
            raise
        except Exception:
            raise PcapToolFailed() from None

    def execute(self, batch_id: str, max_files: int) -> PcapBatchSummary:
        _validate_batch_id(batch_id)
        _validate_max_files(max_files)
        command = self._command(batch_id, max_files)
        try:
            root_handle = _open_quarantine_root(self._config.quarantine_root)
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
                return self._load_summary(root_handle, batch_id, max_files)
            finally:
                _close_handle(root_handle)
        except PcapToolFailed:
            raise
        except Exception:
            raise PcapToolFailed() from None

    def request_cancel(self, batch_id: str) -> None:
        _validate_batch_id(batch_id)
        try:
            root_handle = _open_quarantine_root(self._config.quarantine_root)
            try:
                state_handle = _open_or_create_directory_relative(root_handle, "state")
                try:
                    _create_marker_relative_to(state_handle, f"{batch_id}.cancel")
                finally:
                    _close_handle(state_handle)
            finally:
                _close_handle(root_handle)
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
            "-StateId",
            self._checkpoint_scope_id,
            "-MaxFiles",
            str(max_files),
        ]

    def _load_summary(
        self, root_handle: wintypes.HANDLE, batch_id: str, max_files: int
    ) -> PcapBatchSummary:
        output_handle = _open_directory_relative(root_handle, "output")
        try:
            payload = json.loads(
                _read_file_relative(output_handle, f"pcap-batch-{batch_id}.json")
            )
        finally:
            _close_handle(output_handle)
        summary = PcapBatchSummary.model_validate(payload)
        if summary.batch_id != batch_id or summary.selected_count > max_files:
            raise PcapToolFailed()
        return summary


def _validate_batch_id(batch_id: str) -> None:
    if type(batch_id) is not str or _BATCH_ID.fullmatch(batch_id) is None:
        raise ValueError("batch_id must be a valid public batch identifier")


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 20")


def _checkpoint_scope_id(config: PcapConfig) -> str:
    digest = hashlib.sha256()
    digest.update(b"pcap-private-checkpoint-scope-v1\0")
    for path in (
        config.quarantine_root,
        config.powershell_executable,
        config.batch_script,
        config.inspect_script,
    ):
        normalized = os.path.normcase(str(path.resolve())).encode("utf-8")
        digest.update(len(normalized).to_bytes(4, "big"))
        digest.update(normalized)
    return "state_" + digest.hexdigest()[:32]


def _count_pending_files(input_root: Path) -> int:
    root_metadata = input_root.lstat()
    if _is_reparse_metadata(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        return 0

    count = 0
    pending_directories = [input_root]
    while pending_directories:
        directory = pending_directories.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or _is_reparse_metadata(metadata):
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    pending_directories.append(Path(entry.path))
                elif (
                    stat.S_ISREG(metadata.st_mode)
                    and Path(entry.name).suffix.lower() in _PCAP_EXTENSIONS
                ):
                    count += 1
                    if count > _MAX_PENDING_FILE_COUNT:
                        raise PcapToolFailed()
    return count


def _is_reparse_metadata(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )
