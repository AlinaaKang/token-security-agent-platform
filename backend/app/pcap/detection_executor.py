from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from pathlib import Path
from threading import RLock
from typing import Any

from app.pcap.config import PcapConfig
from app.pcap.detection_models import (
    PcapDetectionFailureCode,
    PcapDetectionOverview,
    PcapDetectionSummary,
    PcapLocalizedEvidence,
    PcapProcessedSample,
)
from app.pcap.executor import _count_pending_files, _is_reparse_metadata


_DETECTION_ID = re.compile(r"^detection_[0-9a-f]{32}$")
_PCAP_EXTENSIONS = frozenset({".pcap", ".pcapng"})
_MAX_FILES = 20
_MAX_OUTPUT_BYTES = 256 * 1024
_MAX_WORKERS = 3


class PcapDetectionToolFailed(RuntimeError):
    def __init__(self, code: str = "tool_failed") -> None:
        self.code = code
        super().__init__("pcap_detection_failed")


class _PcapDetectionSampleFailed(RuntimeError):
    def __init__(self, code: PcapDetectionFailureCode) -> None:
        self.code = code
        super().__init__("pcap_detection_sample_failed")


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

    def execute(
        self,
        detection_id: str,
        max_files: int,
        on_progress: Callable[[PcapDetectionSummary], None] | None = None,
        start_index: int = 0,
    ) -> PcapDetectionSummary:
        _validate_detection_id(detection_id)
        _validate_max_files(max_files)
        try:
            capture_paths = _capture_paths(
                self._config.quarantine_root / "input", max_files, start_index
            )
        except Exception:
            raise PcapDetectionToolFailed() from None

        results: list[
            tuple[
                bool,
                tuple[PcapLocalizedEvidence, ...],
                PcapDetectionFailureCode | None,
            ]
        ] = []
        try:
            # A small fixed pool keeps Docker resource use bounded while avoiding
            # paying container startup cost serially for every capture.
            if capture_paths:
                with ThreadPoolExecutor(
                    max_workers=min(_MAX_WORKERS, len(capture_paths)),
                    thread_name_prefix="pcap-file",
                ) as pool:
                    futures = {
                        pool.submit(self._inspect_capture, path): index
                        for index, path in enumerate(capture_paths)
                    }
                    completed: dict[int, tuple[bool, tuple[PcapLocalizedEvidence, ...], PcapDetectionFailureCode | None]] = {}
                    for future in as_completed(futures):
                        index = futures[future]
                        if self._is_cancel_requested(detection_id):
                            break
                        try:
                            completed[index] = (True, future.result(), None)
                        except _PcapDetectionSampleFailed as exc:
                            completed[index] = (False, (), exc.code)
                        except subprocess.TimeoutExpired:
                            completed[index] = (False, (), PcapDetectionFailureCode.TOOL_TIMEOUT)
                        except Exception:
                            completed[index] = (False, (), PcapDetectionFailureCode.TOOL_FAILED)
                        results = [completed[item] for item in sorted(completed)]
                        if on_progress is not None:
                            try:
                                on_progress(_summary_from_results(results))
                            except Exception:
                                pass
        finally:
            with self._lock:
                self._cancel_requested.discard(detection_id)

        return _summary_from_results(results)

    def execute_capture(
        self,
        detection_id: str,
        capture_path: Path,
        on_progress: Callable[[PcapDetectionSummary], None] | None = None,
    ) -> PcapDetectionSummary:
        _validate_detection_id(detection_id)
        try:
            _validate_uploaded_capture(
                capture_path,
                self._config.quarantine_root / "uploads",
            )
        except Exception:
            raise PcapDetectionToolFailed() from None

        try:
            result = (True, self._inspect_capture(capture_path), None)
        except _PcapDetectionSampleFailed as exc:
            result = (False, (), exc.code)
        except subprocess.TimeoutExpired:
            result = (False, (), PcapDetectionFailureCode.TOOL_TIMEOUT)
        except Exception:
            result = (False, (), PcapDetectionFailureCode.TOOL_FAILED)
        finally:
            with self._lock:
                self._cancel_requested.discard(detection_id)

        summary = _summary_from_results([result])
        if on_progress is not None:
            try:
                on_progress(summary)
            except Exception:
                pass
        return summary

    def _inspect_capture(self, capture_path: Path) -> tuple[PcapLocalizedEvidence, ...]:
        completed = self._runner(
            self._command(capture_path),
            capture_output=True,
            check=False,
            encoding="utf-8",
            shell=False,
            timeout=160,
        )
        if getattr(completed, "returncode", None) != 0:
            raw = getattr(completed, "stdout", None)
            public_code = raw.strip() if isinstance(raw, str) else ""
            if public_code == "pcap_preflight_error=capture_invalid":
                raise _PcapDetectionSampleFailed(
                    PcapDetectionFailureCode.CAPTURE_INVALID
                )
            if public_code == "pcap_preflight_error=docker_timeout":
                raise _PcapDetectionSampleFailed(PcapDetectionFailureCode.TOOL_TIMEOUT)
            raise _PcapDetectionSampleFailed(PcapDetectionFailureCode.TOOL_FAILED)
        raw = getattr(completed, "stdout", None)
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            raise _PcapDetectionSampleFailed(PcapDetectionFailureCode.REPORT_INVALID)
        try:
            return _parse_detection_report(raw)
        except (json.JSONDecodeError, ValueError):
            raise _PcapDetectionSampleFailed(
                PcapDetectionFailureCode.REPORT_INVALID
            ) from None

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


def _summary_from_results(
    results: list[tuple[bool, tuple[PcapLocalizedEvidence, ...], PcapDetectionFailureCode | None]],
) -> PcapDetectionSummary:
    evidence: list[PcapLocalizedEvidence] = []
    evidence_ids: set[str] = set()
    succeeded_count = 0
    failed_count = 0
    processed_samples: list[PcapProcessedSample] = []
    for index, (success, report_evidence, failure_code) in enumerate(results, 1):
        if not success:
            failed_count += 1
            processed_samples.append(PcapProcessedSample(sample_index=index, status="failed", evidence_count=0, failure_code=failure_code or PcapDetectionFailureCode.TOOL_FAILED))
            continue
        report_ids = {item.evidence_id for item in report_evidence}
        if report_ids.intersection(evidence_ids):
            failed_count += 1
            processed_samples.append(PcapProcessedSample(sample_index=index, status="failed", evidence_count=0, failure_code=PcapDetectionFailureCode.REPORT_INVALID))
            continue
        succeeded_count += 1
        evidence.extend(report_evidence)
        evidence_ids.update(report_ids)
        processed_samples.append(PcapProcessedSample(sample_index=index, status="succeeded", evidence_count=len(report_evidence)))
    return PcapDetectionSummary(
        analyzed_count=len(results),
        succeeded_count=succeeded_count,
        failed_count=failed_count,
        evidence=tuple(evidence),
        processed_samples=tuple(processed_samples),
    )


def _capture_paths(input_root: Path, max_files: int, start_index: int = 0) -> tuple[Path, ...]:
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
    if type(start_index) is not int or start_index < 0:
        raise ValueError("start_index must be a nonnegative integer")
    return tuple(captures[start_index : start_index + max_files])


def _validate_uploaded_capture(capture_path: Path, uploads_root: Path) -> None:
    capture_path = Path(capture_path)
    root_metadata = uploads_root.lstat()
    capture_metadata = capture_path.lstat()
    if _is_reparse_metadata(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("invalid upload root")
    if _is_reparse_metadata(capture_metadata) or not stat.S_ISREG(capture_metadata.st_mode):
        raise ValueError("invalid uploaded capture")
    if capture_path.parent.resolve() != uploads_root.resolve():
        raise ValueError("uploaded capture must be inside upload root")


def _validate_detection_id(detection_id: str) -> None:
    if type(detection_id) is not str or _DETECTION_ID.fullmatch(detection_id) is None:
        raise ValueError("detection_id must be a valid public detection identifier")


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 20")
        succeeded_count = sum(success for success, _ in results)
        failed_count = len(results) - succeeded_count
        for success, report_evidence in results:
            if not success:
                continue
            report_ids = {item.evidence_id for item in report_evidence}
            if report_ids.intersection(evidence_ids):
                failed_count += 1
                succeeded_count -= 1
                continue
            evidence.extend(report_evidence)
            evidence_ids.update(report_ids)
