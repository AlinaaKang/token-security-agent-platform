from __future__ import annotations

import json
from threading import Event, Thread
import time

import pytest

import app.superagent.pcap_coordinator as coordinator_module
from app.pcap.authorization import (
    PcapAuthorizationAlreadyUsed,
    PcapAuthorizationStore,
    PcapAuthorizationUnknown,
)
from app.pcap.executor import PcapToolFailed
from app.pcap.models import (
    PcapBatchSummary,
    PcapMissionResult,
    PcapMissionStatus,
)
from app.superagent.models import PcapTriageMissionRequest
from app.superagent.pcap_coordinator import PcapMissionCoordinator
from app.superagent.service import SuperAgentService
from app.superagent.store import SuperAgentMissionStore


def _summary(*, token_eligible: bool = False) -> PcapBatchSummary:
    return PcapBatchSummary.model_validate(
        {
            "batch_id": "batch_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "selected_count": 1,
            "succeeded_count": 1,
            "failed_count": 0,
            "skipped_count": 0,
            "captures": [
                {
                    "capture_id": "capture_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "status": "succeeded",
                    "packet_count": 4,
                    "protocol_counts": {"http": 1, "tls": 3},
                    "visibility": {
                        "plaintext_application_protocol_observed": token_eligible,
                        "encrypted_transport_observed": True,
                        "tls_observed": True,
                        "quic_observed": False,
                    },
                    "capability": (
                        "token_eligible" if token_eligible else "traffic_only"
                    ),
                }
            ],
        }
    )


class BlockingExecutor:
    def __init__(
        self,
        *,
        summary: PcapBatchSummary | None = None,
        failure: bool = False,
        cancel_failure: bool = False,
    ) -> None:
        self.summary = summary or _summary()
        self.failure = failure
        self.cancel_failure = cancel_failure
        self.started = Event()
        self.release = Event()
        self.executions: list[tuple[str, int]] = []
        self.cancelled: list[str] = []

    def execute(self, batch_id: str, max_files: int) -> PcapBatchSummary:
        self.executions.append((batch_id, max_files))
        self.started.set()
        if not self.release.wait(timeout=3):
            raise AssertionError("test executor was not released")
        if self.failure:
            raise PcapToolFailed()
        return self.summary.model_copy(update={"batch_id": batch_id})

    def request_cancel(self, batch_id: str) -> None:
        if self.cancel_failure:
            raise PcapToolFailed()
        self.cancelled.append(batch_id)
        self.release.set()


class InvalidThenValidExecutor(BlockingExecutor):
    def execute(self, batch_id: str, max_files: int) -> object:
        summary = super().execute(batch_id, max_files)
        if len(self.executions) == 1:
            return object()
        return summary


def _request(authorization_id: str) -> PcapTriageMissionRequest:
    return PcapTriageMissionRequest(
        objective="triage_pcap_evidence",
        authorization_id=authorization_id,
    )


def _wait_for_status(
    store: SuperAgentMissionStore,
    mission_id: str,
    expected: PcapMissionStatus,
) -> PcapMissionResult:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        mission = store.get(mission_id)
        assert isinstance(mission, PcapMissionResult)
        if mission.status is expected:
            return mission
        time.sleep(0.01)
    raise AssertionError(f"mission did not reach {expected}")


def _coordinator(
    executor: BlockingExecutor,
) -> tuple[PcapMissionCoordinator, PcapAuthorizationStore, SuperAgentMissionStore]:
    authorizations = PcapAuthorizationStore()
    store = SuperAgentMissionStore()
    coordinator = PcapMissionCoordinator(
        authorization_store=authorizations,
        executor=executor,
        mission_store=store,
    )
    return coordinator, authorizations, store


def test_start_persists_queued_running_and_completed_public_snapshots() -> None:
    executor = BlockingExecutor()
    coordinator, authorizations, store = _coordinator(executor)
    receipt = authorizations.issue(max_files=7)
    try:
        queued = coordinator.start(_request(receipt.authorization_id))
        assert queued.status is PcapMissionStatus.QUEUED

        assert executor.started.wait(timeout=3)
        running = _wait_for_status(store, queued.mission_id, PcapMissionStatus.RUNNING)
        assert running.status is PcapMissionStatus.RUNNING

        executor.release.set()
        completed = _wait_for_status(
            store, queued.mission_id, PcapMissionStatus.COMPLETED
        )
    finally:
        executor.release.set()
        coordinator.close()

    assert executor.executions == [(queued.batch_id, 7)]
    assert completed.summary is not None
    assert completed.summary.batch_id == queued.batch_id


def test_completed_events_are_deterministic_bounded_and_role_ordered() -> None:
    executor = BlockingExecutor()
    coordinator, authorizations, store = _coordinator(executor)
    receipt = authorizations.issue(max_files=1)
    try:
        queued = coordinator.start(_request(receipt.authorization_id))
        assert executor.started.wait(timeout=3)
        executor.release.set()
        completed = _wait_for_status(
            store, queued.mission_id, PcapMissionStatus.COMPLETED
        )
    finally:
        executor.release.set()
        coordinator.close()

    assert [
        (
            event.sequence,
            event.actor.value,
            event.status,
            event.summary.value,
            event.tool_id.value if event.tool_id is not None else None,
        )
        for event in completed.events
    ] == [
        (1, "coordinator", "succeeded", "coordinator_plan", None),
        (
            2,
            "coordinator",
            "succeeded",
            "tool_authorization_accepted",
            "pcap_batch_triage",
        ),
        (
            3,
            "network_evidence_analyst",
            "succeeded",
            "traffic_only_evidence",
            None,
        ),
        (
            4,
            "knowledge_analyst",
            "succeeded",
            "evidence_level_validated",
            None,
        ),
        (
            5,
            "response_operator",
            "succeeded",
            "deterministic_response_ready",
            None,
        ),
        (6, "coordinator", "succeeded", "batch_triage_completed", None),
    ]
    assert len(completed.events) <= 12


def test_token_eligible_stays_a_plaintext_candidate_without_token_claims() -> None:
    executor = BlockingExecutor(summary=_summary(token_eligible=True))
    coordinator, authorizations, store = _coordinator(executor)
    receipt = authorizations.issue(max_files=1)
    try:
        queued = coordinator.start(_request(receipt.authorization_id))
        assert executor.started.wait(timeout=3)
        executor.release.set()
        completed = _wait_for_status(
            store, queued.mission_id, PcapMissionStatus.COMPLETED
        )
    finally:
        executor.release.set()
        coordinator.close()

    assert completed.report.candidates == (
        "plaintext_application_protocol_candidate_not_proven_llm_traffic",
    )
    assert completed.report.unknowns == (
        "cpd_evidence_unavailable",
        "token_evidence_unavailable",
    )
    public_json = json.dumps(completed.model_dump(mode="json"), ensure_ascii=False)
    assert "jailbreak" not in public_json.lower()
    assert "token_anomaly" not in public_json.lower()
    assert "token_text" not in public_json.lower()


def test_tool_failure_degrades_to_the_fixed_public_report() -> None:
    executor = BlockingExecutor(failure=True)
    coordinator, authorizations, store = _coordinator(executor)
    receipt = authorizations.issue(max_files=1)
    try:
        queued = coordinator.start(_request(receipt.authorization_id))
        assert executor.started.wait(timeout=3)
        executor.release.set()
        degraded = _wait_for_status(
            store, queued.mission_id, PcapMissionStatus.DEGRADED
        )
    finally:
        executor.release.set()
        coordinator.close()

    assert degraded.summary is None
    assert degraded.report.model_dump(mode="json") == {
        "confirmed": [],
        "candidates": [],
        "unknowns": [
            "insufficient_evidence",
            "cpd_evidence_unavailable",
            "token_evidence_unavailable",
        ],
        "recommended_action": ["retain_public_metadata"],
    }
    assert degraded.events[-1].actor.value == "coordinator"
    assert degraded.events[-1].status == "failed"


def test_cancel_sets_marker_and_cancelled_state_without_worker_overwrite() -> None:
    executor = BlockingExecutor(failure=True)
    coordinator, authorizations, store = _coordinator(executor)
    receipt = authorizations.issue(max_files=1)
    untouched = PcapMissionResult(
        mission_id="mission_cccccccccccccccccccccccccccccccc",
        status="queued",
        batch_id="batch_cccccccccccccccccccccccccccccccc",
        events=(),
        report={},
        limitations=("no_packet_payload_retained",),
        created_at="2026-09-01T00:00:00Z",
    )
    store.put(untouched)
    try:
        queued = coordinator.start(_request(receipt.authorization_id))
        assert executor.started.wait(timeout=3)

        cancelled = coordinator.cancel(queued.mission_id)
        after_worker = _wait_for_status(
            store, queued.mission_id, PcapMissionStatus.CANCELLED
        )
    finally:
        executor.release.set()
        coordinator.close()

    assert executor.cancelled == [queued.batch_id]
    assert cancelled.status is PcapMissionStatus.CANCELLED
    assert after_worker.status is PcapMissionStatus.CANCELLED
    assert store.get(untouched.mission_id) is untouched


def test_cancel_marker_failure_degrades_without_later_terminal_overwrite() -> None:
    executor = BlockingExecutor(cancel_failure=True)
    coordinator, authorizations, store = _coordinator(executor)
    receipt = authorizations.issue(max_files=1)
    queued = coordinator.start(_request(receipt.authorization_id))
    assert executor.started.wait(timeout=3)

    degraded = coordinator.cancel(queued.mission_id)
    executor.release.set()
    coordinator.close()

    assert degraded.status is PcapMissionStatus.DEGRADED
    persisted = store.get(queued.mission_id)
    assert isinstance(persisted, PcapMissionResult)
    assert persisted.status is PcapMissionStatus.DEGRADED


def test_queued_marker_failure_never_revives_or_reaches_the_executor() -> None:
    executor = BlockingExecutor(cancel_failure=True)
    coordinator, authorizations, store = _coordinator(executor)
    first_receipt = authorizations.issue(max_files=1)
    second_receipt = authorizations.issue(max_files=1)
    third_receipt = authorizations.issue(max_files=1)
    first = coordinator.start(_request(first_receipt.authorization_id))
    assert executor.started.wait(timeout=3)
    second = coordinator.start(_request(second_receipt.authorization_id))
    third = coordinator.start(_request(third_receipt.authorization_id))

    degraded = coordinator.cancel(second.mission_id)
    executor.release.set()
    try:
        _wait_for_status(store, third.mission_id, PcapMissionStatus.COMPLETED)
        persisted = store.get(second.mission_id)
        assert isinstance(persisted, PcapMissionResult)
        assert degraded.status is PcapMissionStatus.DEGRADED
        assert persisted.status is PcapMissionStatus.DEGRADED
        assert executor.executions == [
            (first.batch_id, 1),
            (third.batch_id, 1),
        ]
    finally:
        coordinator.close()


def test_close_terminalizes_a_mission_queued_behind_running_work() -> None:
    executor = BlockingExecutor()
    coordinator, authorizations, store = _coordinator(executor)
    first_receipt = authorizations.issue(max_files=1)
    second_receipt = authorizations.issue(max_files=1)
    first = coordinator.start(_request(first_receipt.authorization_id))
    assert executor.started.wait(timeout=3)
    second = coordinator.start(_request(second_receipt.authorization_id))
    closer = Thread(target=coordinator.close)
    try:
        closer.start()
        closer.join(timeout=0.1)
        executor.release.set()
        closer.join(timeout=3)
        assert not closer.is_alive()
    finally:
        executor.release.set()
        closer.join(timeout=3)
        coordinator.close()

    first_result = store.get(first.mission_id)
    second_result = store.get(second.mission_id)
    assert isinstance(first_result, PcapMissionResult)
    assert isinstance(second_result, PcapMissionResult)
    assert second_result.status is PcapMissionStatus.CANCELLED
    assert second.batch_id in executor.cancelled


def test_service_uses_the_coordinators_common_store_for_pcap_polling() -> None:
    executor = BlockingExecutor()
    coordinator, authorizations, _ = _coordinator(executor)
    service = SuperAgentService(lab_service=object(), pcap_coordinator=coordinator)
    receipt = authorizations.issue(max_files=1)
    try:
        queued = service.create_mission(_request(receipt.authorization_id))
        restored = service.get_mission(queued.mission_id)
    finally:
        executor.release.set()
        coordinator.close()

    assert isinstance(restored, PcapMissionResult)
    assert restored.mission_id == queued.mission_id


def test_coordinator_applies_capacity_backpressure_before_authorization_use() -> None:
    executor = BlockingExecutor()
    authorizations = PcapAuthorizationStore()
    store = SuperAgentMissionStore(capacity=2)
    coordinator = PcapMissionCoordinator(
        authorization_store=authorizations,
        executor=executor,
        mission_store=store,
    )
    first_receipt = authorizations.issue(max_files=1)
    retryable_receipt = authorizations.issue(max_files=1)
    first = coordinator.start(_request(first_receipt.authorization_id))
    assert executor.started.wait(timeout=3)
    try:
        with pytest.raises(RuntimeError, match="pcap_mission_capacity_reached"):
            coordinator.start(_request(retryable_receipt.authorization_id))
        assert executor.executions == [(first.batch_id, 1)]

        executor.release.set()
        _wait_for_status(store, first.mission_id, PcapMissionStatus.COMPLETED)
        second = coordinator.start(_request(retryable_receipt.authorization_id))
        _wait_for_status(store, second.mission_id, PcapMissionStatus.COMPLETED)
    finally:
        executor.release.set()
        coordinator.close()

    assert executor.executions == [
        (first.batch_id, 1),
        (second.batch_id, 1),
    ]


def test_invalid_executor_result_degrades_and_releases_admission_slot() -> None:
    executor = InvalidThenValidExecutor()
    authorizations = PcapAuthorizationStore()
    store = SuperAgentMissionStore(capacity=2)
    coordinator = PcapMissionCoordinator(
        authorization_store=authorizations,
        executor=executor,
        mission_store=store,
    )
    first_receipt = authorizations.issue(max_files=1)
    second_receipt = authorizations.issue(max_files=1)
    try:
        first = coordinator.start(_request(first_receipt.authorization_id))
        assert executor.started.wait(timeout=3)
        executor.release.set()
        degraded = _wait_for_status(
            store, first.mission_id, PcapMissionStatus.DEGRADED
        )

        second = coordinator.start(_request(second_receipt.authorization_id))
        completed = _wait_for_status(
            store, second.mission_id, PcapMissionStatus.COMPLETED
        )
    finally:
        executor.release.set()
        coordinator.close()

    assert degraded.summary is None
    assert completed.summary is not None


def test_event_transformation_failure_uses_prevalidated_terminal_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = BlockingExecutor()
    authorizations = PcapAuthorizationStore()
    store = SuperAgentMissionStore(capacity=2)
    coordinator = PcapMissionCoordinator(
        authorization_store=authorizations,
        executor=executor,
        mission_store=store,
    )
    first_receipt = authorizations.issue(max_files=1)
    second_receipt = authorizations.issue(max_files=1)
    original_terminal_events = coordinator_module._terminal_events

    def fail_event_transformation(**kwargs: object) -> object:
        raise ValueError("synthetic_event_transformation_failed")

    try:
        monkeypatch.setattr(
            coordinator_module,
            "_terminal_events",
            fail_event_transformation,
        )
        first = coordinator.start(_request(first_receipt.authorization_id))
        assert executor.started.wait(timeout=3)
        executor.release.set()
        degraded = _wait_for_status(
            store, first.mission_id, PcapMissionStatus.DEGRADED
        )

        monkeypatch.setattr(
            coordinator_module,
            "_terminal_events",
            original_terminal_events,
        )
        second = coordinator.start(_request(second_receipt.authorization_id))
        completed = _wait_for_status(
            store, second.mission_id, PcapMissionStatus.COMPLETED
        )
    finally:
        monkeypatch.setattr(
            coordinator_module,
            "_terminal_events",
            original_terminal_events,
        )
        executor.release.set()
        coordinator.close()

    assert degraded.events[-1].status == "failed"
    assert completed.status is PcapMissionStatus.COMPLETED


def test_authorization_is_consumed_before_any_executor_access() -> None:
    executor = BlockingExecutor()
    coordinator, authorizations, _ = _coordinator(executor)
    receipt = authorizations.issue(max_files=1)
    try:
        with pytest.raises(PcapAuthorizationUnknown):
            coordinator.start(_request("pcap_auth_" + "f" * 32))
        assert executor.executions == []

        queued = coordinator.start(_request(receipt.authorization_id))
        assert executor.started.wait(timeout=3)
        with pytest.raises(PcapAuthorizationAlreadyUsed):
            coordinator.start(_request(receipt.authorization_id))
    finally:
        executor.release.set()
        coordinator.close()

    assert executor.executions == [(queued.batch_id, 1)]


def test_every_stored_snapshot_excludes_private_capture_fields() -> None:
    executor = BlockingExecutor()
    coordinator, authorizations, store = _coordinator(executor)
    receipt = authorizations.issue(max_files=1)
    try:
        queued = coordinator.start(_request(receipt.authorization_id))
        assert executor.started.wait(timeout=3)
        executor.release.set()
        _wait_for_status(store, queued.mission_id, PcapMissionStatus.COMPLETED)
    finally:
        executor.release.set()
        coordinator.close()

    snapshots = [item.model_dump(mode="json") for item in store.snapshot()]

    def field_names(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(
                *(field_names(item) for item in value.values())
            )
        if isinstance(value, list):
            return set().union(*(field_names(item) for item in value))
        return set()

    assert field_names(snapshots).isdisjoint(
        {"filename", "path", "sha256", "prompt", "payload", "token_text"}
    )
    public_json = json.dumps(snapshots, ensure_ascii=False).lower()
    for private_term in (
        "private_sentinel",
        "203.0.113.10",
        "raw stderr",
        "hidden reasoning",
    ):
        assert private_term not in public_json
