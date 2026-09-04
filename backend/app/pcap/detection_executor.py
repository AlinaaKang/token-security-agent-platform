from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from threading import RLock
from typing import Any

from app.pcap.config import PcapConfig
from app.pcap.detection_models import (
    PcapDetectionOverview,
    PcapDetectionSummary,
    PcapLocalizedEvidence,
)
from app.pcap.executor import _count_pending_files, _is_reparse_metadata


_DETECTION_ID = re.compile(r"^detection_[0-9a-f]{32}$")
_PCAP_EXTENSIONS = frozenset({".pcap", ".pcapng"})
_MAX_FILES = 20
_MAX_OUTPUT_BYTES = 256 * 1024


class PcapDetectionToolFailed(RuntimeError):
    def __init__(self, code: str = "tool_failed") -> None:
        self.code = code
        super().__init__("pcap_detection_failed")


class PcapDetectionExecutor:
    def __init__(
        self,
        *,
        config: PcapConfig,
        runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        self._config = config
        self._runner = runner
        self._cancel_requested: set[str] = set()
        self._lock = RLock()

    def overview(self) -> PcapDetectionOverview:
        try:
            return PcapDetectionOverview(
                enabled=True,
                eligible_file_count=_count_pending_files(
                    self._config.quarantine_root / "input"
                ),
            )
        except Exception:
            raise PcapDetectionToolFailed() from None

    def execute(self, detection_id: str, max_files: int) -> PcapDetectionSummary:
        _validate_detection_id(detection_id)
        _validate_max_files(max_files)
        try:
            capture_paths = _capture_paths(
                self._config.quarantine_root / "input", max_files
            )
        except Exception:
            raise PcapDetectionToolFailed() from None

        succeeded_count = 0
        failed_count = 0
        evidence: list[PcapLocalizedEvidence] = []
        evidence_ids: set[str] = set()
        try:
            for capture_path in capture_paths:
                if self._is_cancel_requested(detection_id):
                    break
                try:
                    completed = self._runner(
                        self._command(capture_path),
                        capture_output=True,
                        check=False,
                        encoding="utf-8",
                        shell=False,
                        timeout=160,
                    )
                    if getattr(completed, "returncode", None) != 0:
                        raise ValueError("tool failed")
                    raw = getattr(completed, "stdout", None)
                    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_OUTPUT_BYTES:
                        raise ValueError("invalid output")
                    report_evidence = _parse_detection_report(raw)
                    report_ids = {item.evidence_id for item in report_evidence}
                    if report_ids.intersection(evidence_ids):
                        raise ValueError("duplicate evidence identifier")
                    evidence.extend(report_evidence)
                    evidence_ids.update(report_ids)
                    succeeded_count += 1
                except Exception:
                    failed_count += 1
        finally:
            with self._lock:
                self._cancel_requested.discard(detection_id)

        return PcapDetectionSummary(
            analyzed_count=succeeded_count + failed_count,
            succeeded_count=succeeded_count,
            failed_count=failed_count,
            evidence=tuple(evidence),
        )

    def request_cancel(self, detection_id: str) -> None:
        _validate_detection_id(detection_id)
        with self._lock:
            self._cancel_requested.add(detection_id)

    def _is_cancel_requested(self, detection_id: str) -> bool:
        with self._lock:
            return detection_id in self._cancel_requested

    def _command(self, capture_path: Path) -> list[str]:
        return [
            str(self._config.powershell_executable),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self._config.inspect_script),
            "-Path",
            str(capture_path),
            "-QuarantineRoot",
            str(self._config.quarantine_root),
            "-Mode",
            "HttpDetection",
        ]


def _parse_detection_report(raw: str) -> tuple[PcapLocalizedEvidence, ...]:
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "verified_packet_count",
        "evidence",
    }:
        raise ValueError("invalid detection report")
    if payload["schema_version"] != 1 or type(payload["verified_packet_count"]) is not int:
        raise ValueError("invalid detection report")
    raw_evidence = payload["evidence"]
    if not isinstance(raw_evidence, list) or len(raw_evidence) > 160:
        raise ValueError("invalid detection report")
    evidence = tuple(PcapLocalizedEvidence.model_validate(item) for item in raw_evidence)
    if any(
        item.verified_packet_count != payload["verified_packet_count"]
        for item in evidence
    ):
        raise ValueError("invalid detection report")
    return evidence


def _capture_paths(input_root: Path, max_files: int) -> tuple[Path, ...]:
    root_metadata = input_root.lstat()
    if _is_reparse_metadata(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("invalid input root")
    captures: list[Path] = []
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
                elif stat.S_ISREG(metadata.st_mode) and Path(entry.name).suffix.lower() in _PCAP_EXTENSIONS:
                    captures.append(Path(entry.path))
    captures.sort(key=lambda path: str(path.relative_to(input_root)).casefold())
    return tuple(captures[:max_files])


def _validate_detection_id(detection_id: str) -> None:
    if type(detection_id) is not str or _DETECTION_ID.fullmatch(detection_id) is None:
        raise ValueError("detection_id must be a valid public detection identifier")


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 20")
