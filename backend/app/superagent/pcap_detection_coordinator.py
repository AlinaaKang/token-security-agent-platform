from __future__ import annotations

import inspect
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from app.pcap.detection_models import (
    PcapDetectionAction,
    PcapDetectionFailureCode,
    PcapDetectionMissionResult,
    PcapDetectionNarrative,
    PcapDetectionReport,
    PcapDetectionSummary,
    PcapDetectionTraceEvent,
    PcapDetectionUnknown,
)
from app.pcap.models import PcapActor, PcapMissionStatus
from app.pcap.upload import PcapUploadHandle
from app.superagent.models import PcapDetectionMissionRequest
from app.superagent.store import SuperAgentMissionNotFound, SuperAgentMissionStore


_TERMINAL_STATUSES = frozenset(
    {PcapMissionStatus.COMPLETED, PcapMissionStatus.CANCELLED, PcapMissionStatus.DEGRADED}
)


class PcapDetectionMissionCoordinator:
    def __init__(
        self,
        *,
        authorization_store: Any,
        executor: Any,
        mission_store: SuperAgentMissionStore | None = None,
        upload_service: Any | None = None,
    ) -> None:
        self._authorization_store = authorization_store
        self._executor = executor
        self._mission_store = mission_store or SuperAgentMissionStore()
        self._upload_service = upload_service
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pcap-detection")
        self._lock = RLock()
        self._closed = False
        self._active_ids: set[str] = set()
        self._cancel_requested: set[str] = set()

    @property
    def mission_store(self) -> SuperAgentMissionStore:
        return self._mission_store

    def start(self, request: PcapDetectionMissionRequest) -> PcapDetectionMissionResult:
        with self._lock:
            if self._closed:
                raise RuntimeError("pcap_detection_unavailable")
            self._authorization_store.assert_usable(
                request.authorization_id, purpose="detection"
            )
            if self._active_ids:
                raise RuntimeError("pcap_detection_active")
            authorization = self._authorization_store.consume(
                request.authorization_id, purpose="detection"
            )
            detection_id = f"detection_{uuid.uuid4().hex}"
            queued = _snapshot(
                detection_id=detection_id,
                status=PcapMissionStatus.QUEUED,
                events=(_event(1, PcapDetectionNarrative.AUTHORIZATION_ACCEPTED, "queued"),),
            )
            self._mission_store.put(queued)
            self._active_ids.add(detection_id)
            self._pool.submit(
                self._run,
                detection_id,
                queued.created_at,
                authorization.max_files,
                request.start_index,
            )
            return queued

    def start_uploaded(self, handle: PcapUploadHandle) -> PcapDetectionMissionResult:
        with self._lock:
            if self._closed or self._upload_service is None:
                raise RuntimeError("pcap_detection_unavailable")
            if self._active_ids:
                raise RuntimeError("pcap_detection_active")
            claimed = self._upload_service.claim(handle.handle_id)
            if claimed != handle:
                self._upload_service.discard(handle.handle_id)
                raise RuntimeError("pcap_upload_invalid")
            detection_id = f"detection_{uuid.uuid4().hex}"
            queued = _snapshot(
                detection_id=detection_id,
                status=PcapMissionStatus.QUEUED,
                events=(_event(1, PcapDetectionNarrative.AUTHORIZATION_ACCEPTED, "queued"),),
            )
            self._mission_store.put(queued)
            self._active_ids.add(detection_id)
            try:
                self._pool.submit(
                    self._run,
                    detection_id,
                    queued.created_at,
                    1,
                    0,
                    handle,
                )
            except Exception:
                self._active_ids.discard(detection_id)
                self._upload_service.discard(handle.handle_id)
                raise
            return queued

    def cancel(self, detection_id: str) -> PcapDetectionMissionResult:
        with self._lock:
            current = self._mission_store.get(detection_id)
            if not isinstance(current, PcapDetectionMissionResult):
                raise SuperAgentMissionNotFound(detection_id)
            if current.status in _TERMINAL_STATUSES:
                return current
            self._executor.request_cancel(detection_id)
            self._cancel_requested.add(detection_id)
            return current

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active = tuple(self._active_ids)
        for detection_id in active:
            try:
                self.cancel(detection_id)
            except Exception:
                pass
        self._pool.shutdown(wait=True, cancel_futures=False)

    def _run(
        self,
        detection_id: str,
        created_at: str,
        max_files: int,
        start_index: int,
        upload_handle: PcapUploadHandle | None = None,
    ) -> None:
        try:
            self._mission_store.put(
                _snapshot(
                    detection_id=detection_id,
                    status=PcapMissionStatus.RUNNING,
                    events=(
                        _event(1, PcapDetectionNarrative.AUTHORIZATION_ACCEPTED, "succeeded"),
                        _event(2, PcapDetectionNarrative.ISOLATED_HTTP_SCAN_RUNNING, "running"),
                    ),
                    created_at=created_at,
                )
            )
            def publish_progress(progress: PcapDetectionSummary) -> None:
                self._mission_store.put(
                    _snapshot(
                        detection_id=detection_id,
                        status=PcapMissionStatus.RUNNING,
                        events=(
                            _event(1, PcapDetectionNarrative.AUTHORIZATION_ACCEPTED, "succeeded"),
                            _event(2, PcapDetectionNarrative.ISOLATED_HTTP_SCAN_RUNNING, "running"),
                        ),
                        summary=progress,
                        report=_report(progress),
                        created_at=created_at,
                    )
                )

            execute = (
                self._executor.execute_capture
                if upload_handle is not None
                else self._executor.execute
            )
            parameters = inspect.signature(execute).parameters
            kwargs = {"on_progress": publish_progress} if "on_progress" in parameters else {}
            if upload_handle is not None:
                summary = execute(
                    detection_id,
                    upload_handle.capture_path,
                    **kwargs,
                )
            elif "start_index" in parameters:
                kwargs["start_index"] = start_index
                summary = execute(detection_id, max_files, **kwargs)
            elif kwargs:
                summary = execute(detection_id, max_files, **kwargs)
            else:
                summary = execute(detection_id, max_files)
            if not isinstance(summary, PcapDetectionSummary):
                raise ValueError("pcap_detection_failed")
            with self._lock:
                cancelled = detection_id in self._cancel_requested
            if cancelled:
                self._finish_cancelled(detection_id, created_at)
            else:
                self._mission_store.put(
                    _snapshot(
                        detection_id=detection_id,
                        status=PcapMissionStatus.COMPLETED,
                        events=tuple(
                            _event(index, narrative, "succeeded")
                            for index, narrative in enumerate(PcapDetectionNarrative, 1)
                        ),
                        summary=summary,
                        report=_report(summary),
                        created_at=created_at,
                    )
                )
        except Exception as failure:
            with self._lock:
                cancelled = detection_id in self._cancel_requested
            if cancelled:
                self._finish_cancelled(detection_id, created_at)
            else:
                self._mission_store.put(
                    _snapshot(
                        detection_id=detection_id,
                        status=PcapMissionStatus.DEGRADED,
                        events=(
                            _event(1, PcapDetectionNarrative.AUTHORIZATION_ACCEPTED, "succeeded"),
                            _event(2, PcapDetectionNarrative.ISOLATED_HTTP_SCAN_RUNNING, "failed"),
                            _event(3, PcapDetectionNarrative.LOCALIZED_EVIDENCE_VALIDATED, "skipped"),
                            _event(4, PcapDetectionNarrative.DETERMINISTIC_FUSION_READY, "skipped"),
                        ),
                        failure_code=getattr(
                            failure, "code", PcapDetectionFailureCode.TOOL_FAILED
                        ),
                        created_at=created_at,
                    )
                )
        finally:
            if upload_handle is not None and self._upload_service is not None:
                self._upload_service.discard(upload_handle.handle_id)
            with self._lock:
                self._active_ids.discard(detection_id)
                self._cancel_requested.discard(detection_id)

    def _finish_cancelled(self, detection_id: str, created_at: str) -> None:
        self._mission_store.put(
            _snapshot(
                detection_id=detection_id,
                status=PcapMissionStatus.CANCELLED,
                events=(
                    _event(1, PcapDetectionNarrative.AUTHORIZATION_ACCEPTED, "succeeded"),
                    _event(2, PcapDetectionNarrative.ISOLATED_HTTP_SCAN_RUNNING, "skipped"),
                ),
                created_at=created_at,
            )
        )


def _report(summary: PcapDetectionSummary) -> PcapDetectionReport:
    evidence_ids = tuple(item.evidence_id for item in summary.evidence)
    unknowns: list[PcapDetectionUnknown] = []
    actions: list[PcapDetectionAction] = []
    if not evidence_ids:
        unknowns.append(PcapDetectionUnknown.NO_LOCALIZED_ATTACK_EVIDENCE)
        actions.append(PcapDetectionAction.ALLOW_NO_RULE_EVIDENCE)
    else:
        actions.append(PcapDetectionAction.REVIEW_LOCALIZED_REQUESTS)
    if summary.failed_count:
        unknowns.append(PcapDetectionUnknown.PARTIAL_FILE_FAILURE)
        actions.append(PcapDetectionAction.RETRY_FAILED_FILES)
    return PcapDetectionReport(
        confirmed_evidence_ids=evidence_ids,
        candidate_evidence_ids=evidence_ids,
        unknowns=tuple(unknowns),
        recommended_actions=tuple(actions),
    )


def _snapshot(
    *,
    detection_id: str,
    status: PcapMissionStatus,
    events: tuple[PcapDetectionTraceEvent, ...],
    summary: PcapDetectionSummary | None = None,
    report: PcapDetectionReport | None = None,
    failure_code: PcapDetectionFailureCode | None = None,
    created_at: str | None = None,
) -> PcapDetectionMissionResult:
    return PcapDetectionMissionResult(
        detection_id=detection_id,
        status=status,
        events=events,
        summary=summary,
        report=report
        or PcapDetectionReport(
            confirmed_evidence_ids=(),
            candidate_evidence_ids=(),
            unknowns=(),
            recommended_actions=(),
        ),
        failure_code=failure_code,
        created_at=created_at or _timestamp(),
    )


def _event(
    sequence: int, narrative: PcapDetectionNarrative, status: str
) -> PcapDetectionTraceEvent:
    return PcapDetectionTraceEvent(
        sequence=sequence,
        actor=PcapActor.COORDINATOR,
        status=status,
        summary=narrative,
    )


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
