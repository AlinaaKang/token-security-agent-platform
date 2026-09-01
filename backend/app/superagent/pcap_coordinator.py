from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import RLock
from typing import Any
import uuid

from app.pcap.models import (
    PcapActor,
    PcapBatchSummary,
    PcapCapability,
    PcapMissionReport,
    PcapMissionResult,
    PcapMissionStatus,
    PcapPublicNarrative,
    PcapToolId,
    PcapTraceEvent,
)
from app.superagent.models import PcapTriageMissionRequest
from app.superagent.store import SuperAgentMissionNotFound, SuperAgentMissionStore


_LIMITATIONS = (
    PcapPublicNarrative.NO_PACKET_PAYLOAD_RETAINED,
    PcapPublicNarrative.INSUFFICIENT_EVIDENCE,
)
_FALLBACK_REPORT = PcapMissionReport(
    unknowns=(PcapPublicNarrative.INSUFFICIENT_EVIDENCE,),
    recommended_action=(PcapPublicNarrative.RETAIN_PUBLIC_METADATA,),
)
_TERMINAL_STATUSES = frozenset(
    {
        PcapMissionStatus.COMPLETED,
        PcapMissionStatus.CANCELLED,
        PcapMissionStatus.DEGRADED,
    }
)


class PcapMissionCoordinator:
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
        self._pool = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="pcap-mission",
        )
        self._lock = RLock()
        self._closed = False
        self._active_mission_ids: set[str] = set()

    @property
    def mission_store(self) -> SuperAgentMissionStore:
        return self._mission_store

    def start(self, request: PcapTriageMissionRequest) -> PcapMissionResult:
        with self._lock:
            if self._closed:
                raise RuntimeError("pcap_coordinator_closed")
            if len(self._active_mission_ids) >= self._mission_store.capacity:
                raise RuntimeError("pcap_mission_capacity_reached")
            authorization = self._authorization_store.consume(
                request.authorization_id
            )
            mission_id = f"mission_{uuid.uuid4().hex}"
            batch_id = f"batch_{uuid.uuid4().hex}"
            queued = _snapshot(
                mission_id=mission_id,
                batch_id=batch_id,
                status=PcapMissionStatus.QUEUED,
                events=_queued_events(),
                report=_FALLBACK_REPORT,
            )
            self._mission_store.put(queued)
            self._active_mission_ids.add(mission_id)
            self._pool.submit(
                self._run,
                mission_id,
                batch_id,
                authorization.max_files,
                queued.created_at,
            )
            return queued

    def cancel(self, mission_id: str) -> PcapMissionResult:
        with self._lock:
            current = self._mission_store.get(mission_id)
            if not isinstance(current, PcapMissionResult):
                raise SuperAgentMissionNotFound(mission_id)
            if current.status in _TERMINAL_STATUSES:
                self._active_mission_ids.discard(mission_id)
                return current
            try:
                self._executor.request_cancel(current.batch_id)
            except Exception:
                degraded = _snapshot(
                    mission_id=current.mission_id,
                    batch_id=current.batch_id,
                    status=PcapMissionStatus.DEGRADED,
                    events=_terminal_events(succeeded=False),
                    report=_FALLBACK_REPORT,
                    created_at=current.created_at,
                )
                self._mission_store.put(degraded)
                self._active_mission_ids.discard(mission_id)
                return degraded
            cancelled = _snapshot(
                mission_id=current.mission_id,
                batch_id=current.batch_id,
                status=PcapMissionStatus.CANCELLED,
                events=_cancelled_events(),
                report=_FALLBACK_REPORT,
                created_at=current.created_at,
            )
            self._mission_store.put(cancelled)
            self._active_mission_ids.discard(mission_id)
            return cancelled

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active_mission_ids = tuple(self._active_mission_ids)
        for mission_id in active_mission_ids:
            self.cancel(mission_id)
        self._pool.shutdown(wait=True, cancel_futures=True)

    def _run(
        self,
        mission_id: str,
        batch_id: str,
        max_files: int,
        created_at: str,
    ) -> None:
        with self._lock:
            current = self._mission_store.get(mission_id)
            if (
                not isinstance(current, PcapMissionResult)
                or current.status in _TERMINAL_STATUSES
            ):
                self._active_mission_ids.discard(mission_id)
                return
            self._mission_store.put(
                _snapshot(
                    mission_id=mission_id,
                    batch_id=batch_id,
                    status=PcapMissionStatus.RUNNING,
                    events=_running_events(),
                    report=_FALLBACK_REPORT,
                    created_at=created_at,
                )
            )

        try:
            summary = self._executor.execute(batch_id, max_files)
        except Exception:
            self._finish(
                mission_id=mission_id,
                batch_id=batch_id,
                status=PcapMissionStatus.DEGRADED,
                events=_terminal_events(succeeded=False),
                report=_FALLBACK_REPORT,
                summary=None,
                created_at=created_at,
            )
            return

        self._finish(
            mission_id=mission_id,
            batch_id=batch_id,
            status=PcapMissionStatus.COMPLETED,
            events=_terminal_events(succeeded=True, summary=summary),
            report=_report_for(summary),
            summary=summary,
            created_at=created_at,
        )

    def _finish(
        self,
        *,
        mission_id: str,
        batch_id: str,
        status: PcapMissionStatus,
        events: tuple[PcapTraceEvent, ...],
        report: PcapMissionReport,
        summary: PcapBatchSummary | None,
        created_at: str,
    ) -> None:
        with self._lock:
            current = self._mission_store.get(mission_id)
            if (
                isinstance(current, PcapMissionResult)
                and current.status in _TERMINAL_STATUSES
            ):
                self._active_mission_ids.discard(mission_id)
                return
            self._mission_store.put(
                _snapshot(
                    mission_id=mission_id,
                    batch_id=batch_id,
                    status=status,
                    events=events,
                    report=report,
                    summary=summary,
                    created_at=created_at,
                )
            )
            self._active_mission_ids.discard(mission_id)


def _snapshot(
    *,
    mission_id: str,
    batch_id: str,
    status: PcapMissionStatus,
    events: tuple[PcapTraceEvent, ...],
    report: PcapMissionReport,
    summary: PcapBatchSummary | None = None,
    created_at: str | None = None,
) -> PcapMissionResult:
    return PcapMissionResult(
        mission_id=mission_id,
        status=status,
        batch_id=batch_id,
        events=events,
        summary=summary,
        report=report,
        limitations=_LIMITATIONS,
        created_at=created_at or _timestamp(),
    )


def _queued_events() -> tuple[PcapTraceEvent, ...]:
    return (
        _event(
            1,
            actor=PcapActor.COORDINATOR,
            status="queued",
            summary=PcapPublicNarrative.INSUFFICIENT_EVIDENCE,
        ),
    )


def _running_events() -> tuple[PcapTraceEvent, ...]:
    return (
        _event(
            1,
            actor=PcapActor.COORDINATOR,
            status="succeeded",
            summary=PcapPublicNarrative.INSUFFICIENT_EVIDENCE,
        ),
        _event(
            2,
            actor=PcapActor.COORDINATOR,
            status="running",
            summary=PcapPublicNarrative.RETAIN_PUBLIC_METADATA,
            tool_id=PcapToolId.PCAP_BATCH_TRIAGE,
        ),
    )


def _terminal_events(
    *,
    succeeded: bool,
    summary: PcapBatchSummary | None = None,
) -> tuple[PcapTraceEvent, ...]:
    observation = (
        _observation_for(summary)
        if succeeded and summary is not None
        else PcapPublicNarrative.INSUFFICIENT_EVIDENCE
    )
    return (
        _event(
            1,
            actor=PcapActor.COORDINATOR,
            status="succeeded",
            summary=PcapPublicNarrative.INSUFFICIENT_EVIDENCE,
        ),
        _event(
            2,
            actor=PcapActor.COORDINATOR,
            status="succeeded",
            summary=PcapPublicNarrative.RETAIN_PUBLIC_METADATA,
            tool_id=PcapToolId.PCAP_BATCH_TRIAGE,
        ),
        _event(
            3,
            actor=PcapActor.NETWORK_EVIDENCE_ANALYST,
            status="succeeded" if succeeded else "failed",
            summary=observation,
        ),
        _event(
            4,
            actor=PcapActor.KNOWLEDGE_ANALYST,
            status="succeeded" if succeeded else "skipped",
            summary=PcapPublicNarrative.INSUFFICIENT_EVIDENCE,
        ),
        _event(
            5,
            actor=PcapActor.RESPONSE_OPERATOR,
            status="succeeded",
            summary=PcapPublicNarrative.RETAIN_PUBLIC_METADATA,
        ),
        _event(
            6,
            actor=PcapActor.COORDINATOR,
            status="succeeded" if succeeded else "failed",
            summary=(
                PcapPublicNarrative.BATCH_TRIAGE_COMPLETED
                if succeeded
                else PcapPublicNarrative.INSUFFICIENT_EVIDENCE
            ),
        ),
    )


def _cancelled_events() -> tuple[PcapTraceEvent, ...]:
    events = list(_terminal_events(succeeded=False))
    events[2] = events[2].model_copy(update={"status": "skipped"})
    events[5] = events[5].model_copy(update={"status": "skipped"})
    return tuple(events)


def _event(
    sequence: int,
    *,
    actor: PcapActor,
    status: str,
    summary: PcapPublicNarrative,
    tool_id: PcapToolId | None = None,
) -> PcapTraceEvent:
    return PcapTraceEvent(
        sequence=sequence,
        actor=actor,
        status=status,
        summary=summary,
        tool_id=tool_id,
    )


def _observation_for(summary: PcapBatchSummary) -> PcapPublicNarrative:
    capabilities = {capture.capability for capture in summary.captures}
    if PcapCapability.TOKEN_ELIGIBLE in capabilities:
        return PcapPublicNarrative.PLAINTEXT_APPLICATION_PROTOCOL_OBSERVED
    if PcapCapability.TRAFFIC_ONLY in capabilities:
        return PcapPublicNarrative.TRAFFIC_ONLY_EVIDENCE
    return PcapPublicNarrative.INSUFFICIENT_EVIDENCE


def _report_for(summary: PcapBatchSummary) -> PcapMissionReport:
    capabilities = {capture.capability for capture in summary.captures}
    confirmed = [PcapPublicNarrative.BATCH_TRIAGE_COMPLETED]
    if any(
        capture.visibility.encrypted_transport_observed
        for capture in summary.captures
    ):
        confirmed.append(PcapPublicNarrative.ENCRYPTED_TRANSPORT_OBSERVED)
    if PcapCapability.TRAFFIC_ONLY in capabilities:
        confirmed.append(PcapPublicNarrative.TRAFFIC_ONLY_EVIDENCE)
    candidates = (
        (PcapPublicNarrative.PLAINTEXT_APPLICATION_PROTOCOL_OBSERVED,)
        if PcapCapability.TOKEN_ELIGIBLE in capabilities
        else ()
    )
    return PcapMissionReport(
        confirmed=tuple(confirmed),
        candidates=candidates,
        unknowns=(PcapPublicNarrative.INSUFFICIENT_EVIDENCE,),
        recommended_action=(PcapPublicNarrative.RETAIN_PUBLIC_METADATA,),
    )


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
