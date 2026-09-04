from __future__ import annotations

import time
from threading import Event

from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.detection_models import PcapDetectionSummary
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
