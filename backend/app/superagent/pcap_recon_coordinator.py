from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import RLock
from typing import Any
import uuid

from app.pcap.recon_models import (
    PcapReconFailureCode,
    PcapReconMissionResult,
    PcapReconNarrative,
    PcapReconSummary,
    PcapReconTraceEvent,
)
from app.pcap.models import PcapActor, PcapMissionStatus
from app.superagent.models import PcapReconMissionRequest
from app.superagent.store import SuperAgentMissionNotFound, SuperAgentMissionStore


_TERMINAL_STATUSES = frozenset(
    {PcapMissionStatus.COMPLETED, PcapMissionStatus.CANCELLED, PcapMissionStatus.DEGRADED}
)


class PcapReconMissionCoordinator:
    def __init__(
        self,
        *,
        authorization_store: Any,
        executor: Any,
        mission_store: SuperAgentMissionStore | None = None,
    ) -> None:
        self._authorization_store = authorization_store
        self._executor = executor
        self._mission_store = mission_store or SuperAgentMissionStore()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pcap-recon")
        self._lock = RLock()
        self._closed = False
        self._active_recon_ids: set[str] = set()
        self._cancel_requested: set[str] = set()
        self._cancel_failed: set[str] = set()

    @property
    def mission_store(self) -> SuperAgentMissionStore:
        return self._mission_store

    def start(self, request: PcapReconMissionRequest) -> PcapReconMissionResult:
        with self._lock:
            if self._closed:
                raise RuntimeError("pcap_reconnaissance_unavailable")
            self._authorization_store.assert_usable(
                request.authorization_id, purpose="reconnaissance"
            )
            if self._active_recon_ids:
                raise RuntimeError("pcap_reconnaissance_active")
            self._authorization_store.consume(
                request.authorization_id, purpose="reconnaissance"
            )
            recon_id = f"recon_{uuid.uuid4().hex}"
            queued = _snapshot(
                recon_id=recon_id,
                status=PcapMissionStatus.QUEUED,
                events=_queued_events(),
            )
            self._mission_store.put(queued)
            self._active_recon_ids.add(recon_id)
            self._pool.submit(self._run, recon_id, queued.created_at, 20)
            return queued

    def cancel(self, recon_id: str) -> PcapReconMissionResult:
        with self._lock:
            current = self._mission_store.get(recon_id)
            if not isinstance(current, PcapReconMissionResult):
                raise SuperAgentMissionNotFound(recon_id)
            if current.status in _TERMINAL_STATUSES:
                self._active_recon_ids.discard(recon_id)
                return current
            try:
                self._executor.request_cancel(recon_id)
            except Exception:
                self._cancel_failed.add(recon_id)
                return current
            self._cancel_requested.add(recon_id)
            return current

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active = tuple(self._active_recon_ids)
        for recon_id in active:
            self.cancel(recon_id)
        self._pool.shutdown(wait=True, cancel_futures=False)

    def _run(self, recon_id: str, created_at: str, max_files: int) -> None:
        try:
            self._run_mission(recon_id, created_at, max_files)
        except Exception as failure:
            with self._lock:
                cancelled = recon_id in self._cancel_requested
            try:
                self._finish(
                    recon_id=recon_id,
                    created_at=created_at,
                    status=PcapMissionStatus.CANCELLED if cancelled else PcapMissionStatus.DEGRADED,
                    events=_cancelled_events() if cancelled else _failed_events(),
                    summary=None,
                    failure_code=getattr(failure, "code", PcapReconFailureCode.TOOL_FAILED),
                )
            except Exception:
                pass
        finally:
            with self._lock:
                self._active_recon_ids.discard(recon_id)

    def _run_mission(self, recon_id: str, created_at: str, max_files: int) -> None:
        with self._lock:
            current = self._mission_store.get(recon_id)
            if not isinstance(current, PcapReconMissionResult) or current.status in _TERMINAL_STATUSES:
                self._active_recon_ids.discard(recon_id)
                return
            if recon_id in self._cancel_failed:
                self._finish(
                    recon_id=recon_id,
                    created_at=created_at,
                    status=PcapMissionStatus.DEGRADED,
                    events=_failed_events(),
                    summary=None,
                )
                return
            self._mission_store.put(
                _snapshot(recon_id=recon_id, status=PcapMissionStatus.RUNNING, events=_running_events(), created_at=created_at)
            )
        summary = self._executor.execute(recon_id, max_files)
        if not isinstance(summary, PcapReconSummary):
            raise ValueError("pcap_reconnaissance_failed")
        with self._lock:
            cancelled = recon_id in self._cancel_requested
        self._finish(
            recon_id=recon_id,
            created_at=created_at,
            status=PcapMissionStatus.CANCELLED if cancelled else PcapMissionStatus.COMPLETED,
            events=_cancelled_events() if cancelled else _completed_events(),
            summary=summary,
        )

    def _finish(
        self,
        *,
        recon_id: str,
        created_at: str,
        status: PcapMissionStatus,
        events: tuple[PcapReconTraceEvent, ...],
        summary: PcapReconSummary | None,
        failure_code: PcapReconFailureCode | None = None,
    ) -> None:
        with self._lock:
            current = self._mission_store.get(recon_id)
            if isinstance(current, PcapReconMissionResult) and current.status in _TERMINAL_STATUSES:
                self._active_recon_ids.discard(recon_id)
                return
            if recon_id in self._cancel_requested:
                status, events, summary = PcapMissionStatus.CANCELLED, _cancelled_events(), None
            elif recon_id in self._cancel_failed:
                status, events = PcapMissionStatus.DEGRADED, _failed_events()
            self._mission_store.put(
                _snapshot(recon_id=recon_id, status=status, events=events, summary=summary, failure_code=failure_code, created_at=created_at)
            )
            self._cancel_requested.discard(recon_id)
            self._cancel_failed.discard(recon_id)
            self._active_recon_ids.discard(recon_id)


def _snapshot(*, recon_id: str, status: PcapMissionStatus, events: tuple[PcapReconTraceEvent, ...], summary: PcapReconSummary | None = None, failure_code: PcapReconFailureCode | None = None, created_at: str | None = None) -> PcapReconMissionResult:
    return PcapReconMissionResult(recon_id=recon_id, status=status, events=events, summary=summary, failure_code=failure_code, created_at=created_at or _timestamp())


def _event(sequence: int, summary: PcapReconNarrative, status: str) -> PcapReconTraceEvent:
    return PcapReconTraceEvent(sequence=sequence, actor=PcapActor.COORDINATOR, status=status, summary=summary)


def _queued_events() -> tuple[PcapReconTraceEvent, ...]:
    return (_event(1, PcapReconNarrative.AUTHORIZATION_ACCEPTED, "queued"),)


def _running_events() -> tuple[PcapReconTraceEvent, ...]:
    return (
        _event(1, PcapReconNarrative.AUTHORIZATION_ACCEPTED, "succeeded"),
        _event(2, PcapReconNarrative.QUARTILE_SAMPLE_SELECTED, "succeeded"),
        _event(3, PcapReconNarrative.ISOLATED_FULL_CAPTURE_SCAN_RUNNING, "running"),
    )


def _completed_events() -> tuple[PcapReconTraceEvent, ...]:
    return tuple(_event(i, narrative, "succeeded") for i, narrative in enumerate(PcapReconNarrative, 1))


def _failed_events() -> tuple[PcapReconTraceEvent, ...]:
    return (
        _event(1, PcapReconNarrative.AUTHORIZATION_ACCEPTED, "succeeded"),
        _event(2, PcapReconNarrative.QUARTILE_SAMPLE_SELECTED, "succeeded"),
        _event(3, PcapReconNarrative.ISOLATED_FULL_CAPTURE_SCAN_RUNNING, "failed"),
        _event(4, PcapReconNarrative.AGGREGATE_PROFILE_VALIDATED, "skipped"),
        _event(5, PcapReconNarrative.METHOD_SELECTION_CHECKPOINT_READY, "skipped"),
    )


def _cancelled_events() -> tuple[PcapReconTraceEvent, ...]:
    return (
        _event(1, PcapReconNarrative.AUTHORIZATION_ACCEPTED, "succeeded"),
        _event(2, PcapReconNarrative.QUARTILE_SAMPLE_SELECTED, "skipped"),
        _event(3, PcapReconNarrative.ISOLATED_FULL_CAPTURE_SCAN_RUNNING, "skipped"),
        _event(4, PcapReconNarrative.AGGREGATE_PROFILE_VALIDATED, "skipped"),
        _event(5, PcapReconNarrative.METHOD_SELECTION_CHECKPOINT_READY, "skipped"),
    )


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
