from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi.testclient import TestClient

from app.main import app
from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.detection_models import PcapDetectionOverview, PcapDetectionSummary
from app.schemas import Decision
from app.superagent.pcap_detection_coordinator import PcapDetectionMissionCoordinator
from app.superagent.service import SuperAgentService
from app.superagent.store import SuperAgentMissionStore
from tests.unit.test_superagent_service import FakeLabService


class SyntheticDetectionExecutor:
    def overview(self) -> PcapDetectionOverview:
        return PcapDetectionOverview(enabled=True, eligible_file_count=2318)

    def execute(self, _detection_id: str, _max_files: int) -> PcapDetectionSummary:
        return PcapDetectionSummary.model_validate(
            {
                "analyzed_count": 2,
                "succeeded_count": 1,
                "failed_count": 1,
                "evidence": [
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
                ],
            }
        )

    def request_cancel(self, _detection_id: str) -> None:
        return None


@contextmanager
def installed_detection() -> Iterator[None]:
    authorization_store = PcapAuthorizationStore()
    executor = SyntheticDetectionExecutor()
    mission_store = SuperAgentMissionStore()
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=authorization_store,
        executor=executor,
        mission_store=mission_store,
    )
    service = SuperAgentService(
        lab_service=FakeLabService(decision=Decision.ALLOW),
        mission_store=mission_store,
        pcap_detection_coordinator=coordinator,
    )
    names = (
        "pcap_authorization_store",
        "pcap_detection_executor",
        "pcap_detection_coordinator",
        "superagent_service",
    )
    previous = {name: getattr(app.state, name, None) for name in names}
    app.state.pcap_authorization_store = authorization_store
    app.state.pcap_detection_executor = executor
    app.state.pcap_detection_coordinator = coordinator
    app.state.superagent_service = service
    try:
        yield
    finally:
        coordinator.close()
        for name, value in previous.items():
            if value is None:
                if hasattr(app.state, name):
                    delattr(app.state, name)
            else:
                setattr(app.state, name, value)


def test_detection_api_requires_fresh_authorization_and_returns_localized_result() -> None:
    with installed_detection():
        client = TestClient(app)
        overview = client.get("/api/v1/superagent/pcap/detection/overview")
        receipt = client.post(
            "/api/v1/superagent/pcap/detection/authorizations",
            json={"confirmed": True, "max_files": 2},
        )
        started = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "detect_pcap_anomalies",
                "authorization_id": receipt.json()["authorization_id"],
            },
        )
        mission_url = "/api/v1/superagent/missions/" + started.json()["detection_id"]
        result = client.get(mission_url)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and result.json()["status"] in {
            "queued",
            "running",
        }:
            time.sleep(0.01)
            result = client.get(mission_url)
        reused = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "detect_pcap_anomalies",
                "authorization_id": receipt.json()["authorization_id"],
            },
        )

    assert overview.status_code == 200
    assert overview.json() == {
        "enabled": True,
        "eligible_file_count": 2318,
        "max_files": 20,
        "localization": "request_or_packet",
    }
    assert receipt.status_code == 201
    assert started.status_code == 201
    assert result.status_code == 200
    assert result.json()["objective"] == "detect_pcap_anomalies"
    assert result.json()["summary"]["evidence"][0]["start_packet"] == 2
    assert result.json()["report"]["confirmed_evidence_ids"] == [
        result.json()["summary"]["evidence"][0]["evidence_id"]
    ]
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == "pcap_authorization_used"
    serialized = result.text.casefold()
    for private_key in ("filename", "path", "payload", "uri", "token_text", "stderr"):
        assert private_key not in serialized


def test_triage_authorization_cannot_start_detection() -> None:
    with installed_detection():
        client = TestClient(app)
        receipt = app.state.pcap_authorization_store.issue(1, purpose="triage")
        mismatch = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "detect_pcap_anomalies",
                "authorization_id": receipt.authorization_id,
            },
        )

    assert mismatch.status_code == 403
    assert mismatch.json()["error"]["code"] == "pcap_authorization_purpose_mismatch"
