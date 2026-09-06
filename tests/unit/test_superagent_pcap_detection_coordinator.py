from __future__ import annotations

import time
from pathlib import Path
from threading import Event

import pytest

from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.detection_models import PcapDetectionSummary
from app.pcap.upload import PcapUploadHandle
from app.superagent.models import PcapDetectionMissionRequest
from app.superagent.pcap_detection_coordinator import PcapDetectionMissionCoordinator


def _summary(*, evidence: bool = True, failed_count: int = 0) -> PcapDetectionSummary:
    evidence_items: list[dict[str, object]] = []
    if evidence:
        evidence_items.append(
            {
                "evidence_id": "evidence_0123456789abcdef0123456789abcdef",
                "granularity": "request",
                "verified_packet_count": 3,
                "start_packet": 2,
                "end_packet": 2,
                "start_offset_ms": 100,
                "end_offset_ms": 100,
                "attack_candidate": "sql_injection",
                "detector": "http_rule",
                "confidence": 0.95,
                "supporting_signals": ["sql_syntax_pattern", "request_boundary"],
            }
        )
    succeeded_count = 1
    return PcapDetectionSummary.model_validate(
        {
            "analyzed_count": succeeded_count + failed_count,
            "succeeded_count": succeeded_count,
            "failed_count": failed_count,
            "evidence": evidence_items,
        }
    )


class SyntheticDetectionExecutor:
    def __init__(self, summary: PcapDetectionSummary) -> None:
        self.summary = summary
        self.calls: list[tuple[str, int]] = []

    def execute(self, detection_id: str, max_files: int) -> PcapDetectionSummary:
        self.calls.append((detection_id, max_files))
        return self.summary

    def request_cancel(self, _detection_id: str) -> None:
        return None


class SyntheticUploadService:
    def __init__(self, handle: PcapUploadHandle) -> None:
        self.handle = handle
        self.claims: list[str] = []
        self.discards: list[str] = []

    def claim(self, handle_id: str) -> PcapUploadHandle:
        self.claims.append(handle_id)
        if handle_id != self.handle.handle_id:
            raise RuntimeError("pcap_upload_invalid")
        return self.handle

    def discard(self, handle_id: str) -> None:
        self.discards.append(handle_id)


class UploadedDetectionExecutor(SyntheticDetectionExecutor):
    def __init__(self, summary: PcapDetectionSummary, *, failure: Exception | None = None) -> None:
        super().__init__(summary)
        self.failure = failure
        self.upload_calls: list[tuple[str, Path]] = []

    def execute_capture(
        self,
        detection_id: str,
        capture_path: Path,
        on_progress=None,
    ) -> PcapDetectionSummary:
        self.upload_calls.append((detection_id, capture_path))
        if self.failure is not None:
            raise self.failure
        if on_progress is not None:
            on_progress(self.summary)
        return self.summary


def _wait_terminal(coordinator: PcapDetectionMissionCoordinator, detection_id: str):
    deadline = time.monotonic() + 2
    result = coordinator.mission_store.get(detection_id)
    while time.monotonic() < deadline and result.status in {"queued", "running"}:
        time.sleep(0.01)
        result = coordinator.mission_store.get(detection_id)
    return result


def test_detection_coordinator_fuses_only_real_evidence_ids() -> None:
    authorizations = PcapAuthorizationStore()
    receipt = authorizations.issue(4, purpose="detection")
    executor = SyntheticDetectionExecutor(_summary(failed_count=1))
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=authorizations, executor=executor
    )
    try:
        started = coordinator.start(
            PcapDetectionMissionRequest(
                objective="detect_pcap_anomalies",
                authorization_id=receipt.authorization_id,
            )
        )
        result = _wait_terminal(coordinator, started.detection_id)
    finally:
        coordinator.close()

    assert result.status == "completed"
    assert result.report.confirmed_evidence_ids == (
        "evidence_0123456789abcdef0123456789abcdef",
    )
    assert result.report.candidate_evidence_ids == result.report.confirmed_evidence_ids
    assert result.report.unknowns == ("partial_file_failure",)
    assert result.report.recommended_actions == (
        "review_localized_requests",
        "retry_failed_files",
    )
    assert executor.calls == [(started.detection_id, 4)]


def test_detection_coordinator_does_not_force_alert_without_evidence() -> None:
    authorizations = PcapAuthorizationStore()
    receipt = authorizations.issue(1, purpose="detection")
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=authorizations,
        executor=SyntheticDetectionExecutor(_summary(evidence=False)),
    )
    try:
        started = coordinator.start(
            PcapDetectionMissionRequest(
                objective="detect_pcap_anomalies",
                authorization_id=receipt.authorization_id,
            )
        )
        result = _wait_terminal(coordinator, started.detection_id)
    finally:
        coordinator.close()

    assert result.report.confirmed_evidence_ids == ()
    assert result.report.candidate_evidence_ids == ()
    assert result.report.unknowns == ("no_localized_attack_evidence",)
    assert result.report.recommended_actions == ("allow_no_rule_evidence",)


class BlockingDetectionExecutor(SyntheticDetectionExecutor):
    def __init__(self) -> None:
        super().__init__(_summary())
        self.started = Event()
        self.release = Event()

    def execute(self, detection_id: str, max_files: int) -> PcapDetectionSummary:
        self.started.set()
        self.release.wait(timeout=2)
        return super().execute(detection_id, max_files)


def test_detection_cancellation_publishes_terminal_state_after_worker_cleanup() -> None:
    authorizations = PcapAuthorizationStore()
    receipt = authorizations.issue(1, purpose="detection")
    executor = BlockingDetectionExecutor()
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=authorizations, executor=executor
    )
    try:
        started = coordinator.start(
            PcapDetectionMissionRequest(
                objective="detect_pcap_anomalies",
                authorization_id=receipt.authorization_id,
            )
        )
        assert executor.started.wait(timeout=1)
        acknowledged = coordinator.cancel(started.detection_id)
        executor.release.set()
        terminal = _wait_terminal(coordinator, started.detection_id)
    finally:
        coordinator.close()

    assert acknowledged.status == "running"
    assert terminal.status == "cancelled"
    assert terminal.summary is None


@pytest.mark.parametrize("fails", [False, True])
def test_uploaded_detection_uses_exact_handle_and_discards_it_on_terminal_state(
    tmp_path: Path, fails: bool
) -> None:
    capture = tmp_path / "upload_private.pcap"
    capture.write_bytes(b"capture")
    handle = PcapUploadHandle("pcap_upload_" + "a" * 32, capture, 7, "pcap")
    uploads = SyntheticUploadService(handle)
    executor = UploadedDetectionExecutor(
        _summary(), failure=RuntimeError("tool failed") if fails else None
    )
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=PcapAuthorizationStore(),
        executor=executor,
        upload_service=uploads,
    )
    try:
        started = coordinator.start_uploaded(handle)
        terminal = _wait_terminal(coordinator, started.detection_id)
    finally:
        coordinator.close()

    assert terminal.status == ("degraded" if fails else "completed")
    assert uploads.claims == [handle.handle_id]
    assert uploads.discards == [handle.handle_id]
    assert executor.upload_calls == [(started.detection_id, capture)]
    assert "pcap_upload" not in terminal.model_dump_json()


class BlockingUploadedExecutor(UploadedDetectionExecutor):
    def __init__(self) -> None:
        super().__init__(_summary())
        self.started = Event()
        self.release = Event()

    def execute_capture(self, detection_id: str, capture_path: Path, on_progress=None):
        self.started.set()
        self.release.wait(timeout=2)
        return super().execute_capture(detection_id, capture_path, on_progress)


def test_uploaded_detection_discards_capture_after_cancellation(tmp_path: Path) -> None:
    capture = tmp_path / "upload_private.pcap"
    capture.write_bytes(b"capture")
    handle = PcapUploadHandle("pcap_upload_" + "b" * 32, capture, 7, "pcap")
    uploads = SyntheticUploadService(handle)
    executor = BlockingUploadedExecutor()
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=PcapAuthorizationStore(),
        executor=executor,
        upload_service=uploads,
    )
    try:
        started = coordinator.start_uploaded(handle)
        assert executor.started.wait(timeout=1)
        coordinator.cancel(started.detection_id)
        executor.release.set()
        terminal = _wait_terminal(coordinator, started.detection_id)
    finally:
        coordinator.close()

    assert terminal.status == "cancelled"
    assert uploads.discards == [handle.handle_id]


def test_uploaded_detection_discards_handle_when_scheduling_fails(tmp_path: Path) -> None:
    capture = tmp_path / "upload_private.pcap"
    capture.write_bytes(b"capture")
    handle = PcapUploadHandle("pcap_upload_" + "c" * 32, capture, 7, "pcap")
    uploads = SyntheticUploadService(handle)
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=PcapAuthorizationStore(),
        executor=UploadedDetectionExecutor(_summary()),
        upload_service=uploads,
    )

    class RejectingPool:
        def submit(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("pool closed")

        def shutdown(self, **_kwargs: object) -> None:
            return None

    coordinator._pool = RejectingPool()  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError, match="pool closed"):
            coordinator.start_uploaded(handle)
    finally:
        coordinator.close()

    assert uploads.discards == [handle.handle_id]
