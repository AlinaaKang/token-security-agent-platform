from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.pcap.config import PcapConfig
from app.pcap.executor import _count_pending_files
from app.pcap.recon_models import PcapReconOverview, PcapReconSummary
from app.pcap.windows_handles import (
    _close_handle,
    _create_marker_relative_to,
    _open_directory_relative,
    _open_or_create_directory_relative,
    _open_quarantine_root,
    _read_file_relative,
)


_RECON_ID = re.compile(r"^recon_[0-9a-f]{32}$")
_DEFAULT_SAMPLE_LIMIT = 100
_MAX_FILES = 10_000
_MAX_OUTPUT_BYTES = 256 * 1024


class PcapReconToolFailed(RuntimeError):
    def __init__(self, code: str = "tool_failed") -> None:
        self.code = code
        super().__init__("pcap_recon_failed")


PcapToolFailed = PcapReconToolFailed


def _validate_recon_id(recon_id: str) -> None:
    if type(recon_id) is not str or _RECON_ID.fullmatch(recon_id) is None:
        raise ValueError("recon_id must be a valid public reconnaissance identifier")


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 10000")


def _checkpoint_scope_id(config: PcapConfig) -> str:
    digest = hashlib.sha256()
    digest.update(b"pcap-private-checkpoint-scope-v1\0")
    for path in (
        config.quarantine_root,
        config.powershell_executable,
        config.batch_script,
        config.inspect_script,
        config.recon_batch_script,
    ):
        normalized = os.path.normcase(str(path.resolve())).encode("utf-8")
        digest.update(len(normalized).to_bytes(4, "big"))
        digest.update(normalized)
    return "state_" + digest.hexdigest()[:32]


class PcapReconExecutor:
    def __init__(self, *, config: PcapConfig, runner: Callable[..., Any] = subprocess.run) -> None:
        self._config = config
        self._runner = runner
        self._checkpoint_scope_id = _checkpoint_scope_id(config)

    @property
    def checkpoint_scope_id(self) -> str:
        return self._checkpoint_scope_id

    def overview(self) -> PcapReconOverview:
        try:
            eligible_file_count = _count_pending_files(self._config.quarantine_root / "input")
            return PcapReconOverview(
                enabled=True,
                eligible_file_count=eligible_file_count,
                sample_limit=_DEFAULT_SAMPLE_LIMIT,
                sampling_method="size_quartile_v1",
            )
        except Exception:
            raise PcapReconToolFailed() from None

    def execute(self, recon_id: str, max_files: int = _DEFAULT_SAMPLE_LIMIT) -> PcapReconSummary:
        _validate_recon_id(recon_id)
        _validate_max_files(max_files)
        command = self._command(recon_id, max_files)
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
                    getattr(completed, "returncode", None) != 0
                    or getattr(completed, "stdout", None).strip()
                    != f"pcap_recon_result={recon_id}"
                ):
                    raise PcapReconToolFailed()
                return self._load_summary(root_handle, recon_id, max_files)
            finally:
                _close_handle(root_handle)
        except PcapReconToolFailed:
            raise
        except subprocess.TimeoutExpired:
            raise PcapReconToolFailed("tool_timeout") from None
        except Exception:
            raise PcapReconToolFailed("tool_failed") from None

    def request_cancel(self, recon_id: str) -> None:
        _validate_recon_id(recon_id)
        try:
            root_handle = _open_quarantine_root(self._config.quarantine_root)
            try:
                state_handle = _open_or_create_directory_relative(root_handle, "state")
                try:
                    _create_marker_relative_to(state_handle, f"{recon_id}.cancel")
                finally:
                    _close_handle(state_handle)
            finally:
                _close_handle(root_handle)
        except Exception:
            raise PcapReconToolFailed() from None

    def _command(self, recon_id: str, max_files: int) -> list[str]:
        return [
            str(self._config.powershell_executable),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self._config.recon_batch_script),
            "-QuarantineRoot",
            str(self._config.quarantine_root),
            "-InspectorScript",
            str(self._config.inspect_script),
            "-ReconId",
            recon_id,
            "-StateId",
            self._checkpoint_scope_id,
            "-MaxFiles",
            str(max_files),
        ]

    def _load_summary(
        self, root_handle: Any, recon_id: str, max_files: int
    ) -> PcapReconSummary:
        output_handle = _open_directory_relative(root_handle, "output")
        try:
            raw = _read_file_relative(output_handle, f"pcap-recon-{recon_id}.json")
        finally:
            _close_handle(output_handle)
        if not isinstance(raw, str):
            raise PcapReconToolFailed()
        try:
            if len(raw.encode("utf-8")) > _MAX_OUTPUT_BYTES:
                raise PcapReconToolFailed()
            payload = json.loads(raw)
            summary = PcapReconSummary.model_validate(payload)
            if summary.sampled_count > max_files:
                raise PcapReconToolFailed()
            if sum(summary.quartile_counts.model_dump().values()) != summary.sampled_count:
                raise PcapReconToolFailed()
            for histogram in (
                summary.size_bucket_counts,
                summary.packet_bucket_counts,
                summary.duration_bucket_counts,
            ):
                if sum(histogram.model_dump().values()) != summary.succeeded_count:
                    raise PcapReconToolFailed()
            return summary
        except PcapReconToolFailed:
            raise
        except Exception:
            raise PcapReconToolFailed() from None
