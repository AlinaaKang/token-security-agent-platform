from __future__ import annotations

from threading import Event
import time

import pytest

from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.recon_models import PcapReconSummary
from app.superagent.models import PcapReconMissionRequest
from app.superagent.pcap_recon_coordinator import PcapReconMissionCoordinator
from app.superagent.store import SuperAgentMissionStore


def summary() -> PcapReconSummary:
    return PcapReconSummary.model_validate(
        {
            "sampled_count": 4,
            "succeeded_count": 3,
            "failed_count": 1,
            "quartile_counts": {"quartile_1": 1, "quartile_2": 1, "quartile_3": 1, "quartile_4": 1},
            "size_bucket_counts": {"under_2_kib": 1, "2_kib_to_64_kib": 1, "64_kib_to_1_mib": 1, "at_least_1_mib": 0},
            "packet_bucket_counts": {"empty": 1, "1_to_15": 1, "16_to_63": 1, "at_least_64": 0},
            "duration_bucket_counts": {"zero": 1, "under_1_second": 1, "1_to_10_seconds": 1, "over_10_seconds": 0},
            "protocol_presence_counts": {"dns": 2},
            "plaintext_sample_count": 1,
            "encrypted_sample_count": 1,
            "sequence_candidate_count": 1,
        }
    )


class SyntheticExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def execute(self, recon_id: str, max_files: int) -> PcapReconSummary:
        self.calls.append((recon_id, max_files))
        return summary()

    def request_cancel(self, _recon_id: str) -> None:
        return None


def request(authorization_id: str) -> PcapReconMissionRequest:
    return PcapReconMissionRequest(
        objective="reconnoiter_pcap_dataset", authorization_id=authorization_id
    )


def test_recon_coordinator_runs_one_worker_and_emits_deterministic_report() -> None:
    executor = SyntheticExecutor()
    authorizations = PcapAuthorizationStore()
    coordinator = PcapReconMissionCoordinator(
        authorization_store=authorizations,
        executor=executor,
    )
    try:
        receipt = authorizations.issue(max_files=20, purpose="reconnaissance")
        queued = coordinator.start(request(receipt.authorization_id))
        deadline = time.monotonic() + 2
        completed = queued
        while time.monotonic() < deadline:
            completed = coordinator.mission_store.get(queued.recon_id)
            if completed.status.value == "completed":
                break
            time.sleep(0.01)
        assert completed.status.value == "completed"
        assert [event.summary.value for event in completed.events] == [
            "authorization_accepted",
            "quartile_sample_selected",
            "isolated_full_capture_scan_running",
            "aggregate_profile_validated",
            "method_selection_checkpoint_ready",
        ]
        assert completed.summary == summary()
        assert executor.calls == [(queued.recon_id, 20)]
    finally:
        coordinator.close()

def test_recon_authorization_purpose_mismatch_does_not_consume_receipt() -> None:
    authorizations = PcapAuthorizationStore()
    coordinator = PcapReconMissionCoordinator(
        authorization_store=authorizations,
        executor=SyntheticExecutor(),
    )
    try:
        receipt = authorizations.issue(max_files=20)
        with pytest.raises(RuntimeError, match="pcap_authorization_purpose_mismatch"):
            coordinator.start(request(receipt.authorization_id))
        authorizations.consume(receipt.authorization_id, purpose="triage")
    finally:
        coordinator.close()
