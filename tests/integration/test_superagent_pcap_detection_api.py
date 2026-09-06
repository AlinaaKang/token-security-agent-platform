from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.detection_models import PcapDetectionOverview, PcapDetectionSummary
from app.pcap.upload import PcapUploadService
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

    def execute_capture(
        self, _detection_id: str, _capture_path: Path, on_progress=None
    ) -> PcapDetectionSummary:
        summary = PcapDetectionSummary.model_validate(
            {
                "analyzed_count": 1,
                "succeeded_count": 1,
                "failed_count": 0,
                "evidence": [],
            }
        )
        if on_progress is not None:
            on_progress(summary)
        return summary


@contextmanager
def installed_detection(
    upload_root: Path | None = None, *, upload_max_bytes: int = 128
) -> Iterator[None]:
    authorization_store = PcapAuthorizationStore(upload_max_bytes=upload_max_bytes)
    executor = SyntheticDetectionExecutor()
    mission_store = SuperAgentMissionStore()
    upload_service = (
        PcapUploadService(upload_root, max_bytes=upload_max_bytes)
        if upload_root is not None
        else None
    )
    coordinator = PcapDetectionMissionCoordinator(
        authorization_store=authorization_store,
        executor=executor,
        mission_store=mission_store,
        upload_service=upload_service,
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
        "pcap_upload_service",
        "pcap_upload_max_bytes",
        "superagent_service",
    )
    previous = {name: getattr(app.state, name, None) for name in names}
    app.state.pcap_authorization_store = authorization_store
    app.state.pcap_detection_executor = executor
    app.state.pcap_detection_coordinator = coordinator
    if upload_service is not None:
        app.state.pcap_upload_service = upload_service
        app.state.pcap_upload_max_bytes = upload_max_bytes
    app.state.superagent_service = service
    try:
        yield
    finally:
        coordinator.close()
        if upload_service is not None:
            upload_service.close()
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


def test_upload_capability_is_explicitly_disabled_without_local_upload_service() -> None:
    previous = getattr(app.state, "pcap_upload_service", None)
    if hasattr(app.state, "pcap_upload_service"):
        delattr(app.state, "pcap_upload_service")
    try:
        response = TestClient(app).get(
            "/api/v1/superagent/pcap/detection/upload-capability"
        )
    finally:
        if previous is not None:
            app.state.pcap_upload_service = previous

    assert response.status_code == 200
    assert response.json() == {
        "enabled": False,
        "max_bytes": 0,
        "accepted_formats": ["pcap", "pcapng"],
    }


def _authorize_upload(client: TestClient, byte_count: int):
    return client.post(
        "/api/v1/superagent/pcap/detection/upload-authorizations",
        json={"confirmed": True, "byte_count": byte_count},
    )


def _upload(client: TestClient, authorization_id: str, payload: bytes, **headers: str):
    return client.post(
        "/api/v1/superagent/pcap/detection/uploads",
        content=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "X-PCAP-Authorization": authorization_id,
            **headers,
        },
    )


def test_upload_api_authorizes_raw_capture_and_starts_private_single_file_detection(
    tmp_path: Path,
) -> None:
    payload = bytes.fromhex("a1b2c3d4") + bytes(20)
    with installed_detection(tmp_path):
        client = TestClient(app)
        capability = client.get(
            "/api/v1/superagent/pcap/detection/upload-capability"
        )
        receipt = _authorize_upload(client, len(payload))
        started = _upload(client, receipt.json()["authorization_id"], payload)
        replayed = _upload(client, receipt.json()["authorization_id"], payload)

    assert capability.json() == {
        "enabled": True,
        "max_bytes": 128,
        "accepted_formats": ["pcap", "pcapng"],
    }
    assert receipt.status_code == 201
    assert receipt.json()["max_files"] == 1
    assert started.status_code == 201
    assert started.json()["detection_id"].startswith("detection_")
    assert replayed.status_code == 409
    assert replayed.json()["error"]["code"] == "pcap_authorization_used"
    forbidden_keys = {
        "filename",
        "path",
        "payload",
        "ip",
        "port",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return {str(key).casefold() for key in value} | set().union(
                *(keys(child) for child in value.values())
            )
        if isinstance(value, list):
            return set().union(*(keys(child) for child in value))
        return set()

    assert forbidden_keys.isdisjoint(keys(started.json()))
    assert "pcap_upload_" not in started.text.casefold()


def test_upload_api_accepts_pcapng_and_rejects_unsupported_or_mismatched_bytes(
    tmp_path: Path,
) -> None:
    pcapng = bytes.fromhex("0a0d0d0a") + bytes(24)
    unsupported = b"not-a-capture" + bytes(20)
    with installed_detection(tmp_path):
        client = TestClient(app)
        pcapng_auth = _authorize_upload(client, len(pcapng)).json()["authorization_id"]
        accepted = _upload(client, pcapng_auth, pcapng)
        unsupported_auth = _authorize_upload(client, len(unsupported)).json()["authorization_id"]
        rejected = _upload(client, unsupported_auth, unsupported)
        mismatch_auth = _authorize_upload(client, 24).json()["authorization_id"]
        mismatched = _upload(client, mismatch_auth, bytes.fromhex("a1b2c3d4") + bytes(20), **{"Content-Length": "23"})

    assert accepted.status_code == 201
    assert rejected.status_code == 415
    assert rejected.json()["error"]["code"] == "pcap_format_unsupported"
    assert mismatched.status_code == 400
    assert mismatched.json()["error"]["code"] == "pcap_upload_invalid"


def test_upload_api_returns_fixed_missing_and_oversized_authorization_errors(
    tmp_path: Path,
) -> None:
    payload = bytes.fromhex("a1b2c3d4") + bytes(20)
    with installed_detection(tmp_path, upload_max_bytes=24):
        client = TestClient(app)
        missing = client.post(
            "/api/v1/superagent/pcap/detection/uploads",
            content=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        oversized = _authorize_upload(client, 25)

    assert missing.status_code == 403
    assert missing.json()["error"]["code"] == "pcap_authorization_required"
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "pcap_upload_too_large"
