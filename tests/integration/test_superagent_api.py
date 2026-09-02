from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from threading import Event
import time

import pytest
from fastapi.testclient import TestClient

from app.lab.models import FORBIDDEN_PUBLIC_KEYS
from app.main import app
from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.models import PcapBatchSummary, PcapOverview
from app.schemas import Decision
from app.superagent.pcap_coordinator import PcapMissionCoordinator
from app.superagent.service import SuperAgentService
from app.superagent.store import SuperAgentMissionStore
from tests.unit.test_superagent_service import FakeLabService


_PCAP_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {"filename", "path", "sha256", "payload"}
)


def _forbidden_hits(value: object) -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_PUBLIC_KEYS | _PCAP_FORBIDDEN_PUBLIC_KEYS:
                hits.append(key)
            hits.extend(_forbidden_hits(child))
    elif isinstance(value, list):
        for child in value:
            hits.extend(_forbidden_hits(child))
    return hits


@contextmanager
def installed_superagent(
    service: SuperAgentService | None,
) -> Iterator[None]:
    previous = getattr(app.state, "superagent_service", None)
    if service is None:
        if hasattr(app.state, "superagent_service"):
            del app.state.superagent_service
    else:
        app.state.superagent_service = service
    try:
        yield
    finally:
        if previous is None:
            if hasattr(app.state, "superagent_service"):
                del app.state.superagent_service
        else:
            app.state.superagent_service = previous


@contextmanager
def installed_pcap(
    executor: object,
    *,
    authorization_store: PcapAuthorizationStore | None = None,
) -> Iterator[PcapMissionCoordinator]:
    authorizations = authorization_store or PcapAuthorizationStore()
    coordinator = PcapMissionCoordinator(
        authorization_store=authorizations,
        executor=executor,
    )
    service = SuperAgentService(
        lab_service=FakeLabService(decision=Decision.ALLOW),
        pcap_coordinator=coordinator,
    )
    previous = {
        name: getattr(app.state, name, None)
        for name in (
            "pcap_authorization_store",
            "pcap_executor",
            "pcap_coordinator",
            "superagent_service",
        )
    }
    app.state.pcap_authorization_store = authorizations
    app.state.pcap_executor = executor
    app.state.pcap_coordinator = coordinator
    app.state.superagent_service = service
    try:
        yield coordinator
    finally:
        coordinator.close()
        for name, value in previous.items():
            if value is None:
                if hasattr(app.state, name):
                    delattr(app.state, name)
            else:
                setattr(app.state, name, value)


def _summary(batch_id: str) -> PcapBatchSummary:
    return PcapBatchSummary.model_validate(
        {
            "batch_id": batch_id,
            "selected_count": 1,
            "succeeded_count": 1,
            "failed_count": 0,
            "skipped_count": 0,
            "captures": [
                {
                    "capture_id": "capture_" + "b" * 32,
                    "status": "succeeded",
                    "packet_count": 4,
                    "protocol_counts": {"http": 1, "tls": 3},
                    "visibility": {
                        "plaintext_application_protocol_observed": False,
                        "encrypted_transport_observed": True,
                        "tls_observed": True,
                        "quic_observed": False,
                    },
                    "capability": "traffic_only",
                }
            ],
        }
    )


class SyntheticExecutor:
    def overview(self) -> PcapOverview:
        return PcapOverview(enabled=True, pending_file_count=2318)

    def execute(self, batch_id: str, _max_files: int) -> PcapBatchSummary:
        return _summary(batch_id)

    def request_cancel(self, _batch_id: str) -> None:
        return None


class BlockingSyntheticExecutor(SyntheticExecutor):
    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()

    def execute(self, batch_id: str, _max_files: int) -> PcapBatchSummary:
        self.started.set()
        if not self.release.wait(timeout=3):
            raise RuntimeError("test executor was not released")
        return _summary(batch_id)

    def request_cancel(self, _batch_id: str) -> None:
        return None


class FailingOverviewExecutor(SyntheticExecutor):
    def overview(self) -> PcapOverview:
        raise RuntimeError("PRIVATE_PCAP_PATH_AND_STDERR")


def test_capabilities_and_mission_create_restore_are_public() -> None:
    service = SuperAgentService(
        lab_service=FakeLabService(decision=Decision.BLOCK)
    )
    with installed_superagent(service):
        client = TestClient(app)
        capabilities = client.get("/api/v1/superagent/capabilities")
        created = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "investigate_and_respond",
                "scenario_kind": "frozen",
                "sample_id": "sample_01",
                "mode": "analysis",
            },
        )
        restored = client.get(
            "/api/v1/superagent/missions/" + created.json()["mission_id"]
        )

    assert capabilities.status_code == 200
    assert capabilities.json()["internal_only"] is True
    assert capabilities.json()["max_tool_calls"] == 3
    assert created.status_code == 201
    assert restored.status_code == 200
    assert restored.json() == created.json()
    assert created.json()["final_status"] == "contained"
    assert _forbidden_hits(capabilities.json()) == []
    assert _forbidden_hits(created.json()) == []


def test_unavailable_unknown_and_expired_missions_use_fixed_errors() -> None:
    clock = [0.0]
    service = SuperAgentService(
        lab_service=FakeLabService(decision=Decision.ALLOW),
        mission_store=SuperAgentMissionStore(
            ttl_seconds=1, clock=lambda: clock[0]
        ),
    )
    with installed_superagent(None):
        unavailable = TestClient(app).get(
            "/api/v1/superagent/capabilities"
        )
    with installed_superagent(service):
        client = TestClient(app)
        unknown = client.get(
            "/api/v1/superagent/missions/mission_ffffffffffffffffffffffffffffffff"
        )
        created = client.post(
            "/api/v1/superagent/missions",
            json={
                "scenario_kind": "frozen",
                "sample_id": "synthetic_safe",
                "mode": "analysis",
            },
        )
        clock[0] = 2.0
        expired = client.get(
            "/api/v1/superagent/missions/" + created.json()["mission_id"]
        )

    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "superagent_unavailable"
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "superagent_mission_not_found"
    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "superagent_mission_expired"


def test_mission_api_rejects_free_text_commands_without_reflection() -> None:
    service = SuperAgentService(
        lab_service=FakeLabService(decision=Decision.ALLOW)
    )
    sentinel = "PRIVATE_SUPERAGENT_COMMAND"
    with installed_superagent(service):
        response = TestClient(app).post(
            "/api/v1/superagent/missions",
            json={
                "scenario_kind": "frozen",
                "sample_id": "synthetic_safe",
                "mode": "analysis",
                "command": sentinel,
                "hidden_reasoning": sentinel,
            },
        )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "request_validation_failed",
            "message": "request validation failed",
        }
    }
    assert sentinel not in response.text


def test_pcap_api_is_unavailable_without_configuration_and_preserves_prompt_capabilities() -> None:
    service = SuperAgentService(
        lab_service=FakeLabService(decision=Decision.ALLOW)
    )
    with installed_superagent(service):
        for name in (
            "pcap_authorization_store",
            "pcap_executor",
            "pcap_coordinator",
        ):
            if hasattr(app.state, name):
                delattr(app.state, name)
        client = TestClient(app)
        prompt = client.get("/api/v1/superagent/capabilities")
        pcap = client.get("/api/v1/superagent/pcap/capabilities")

    assert prompt.json() == {
        "ready": True,
        "internal_only": True,
        "objectives": ["investigate_and_respond"],
        "actors": [
            "coordinator",
            "semantic_analyst",
            "token_analyst",
            "knowledge_analyst",
            "response_operator",
        ],
        "max_tool_calls": 3,
        "max_trace_events": 12,
        "replanning_limit": 1,
    }
    assert pcap.status_code == 503
    assert pcap.json()["error"]["code"] == "pcap_triage_unavailable"
    assert _forbidden_hits(pcap.json()) == []


def test_pcap_mission_requires_one_time_authorization_and_supports_polling() -> None:
    with installed_pcap(SyntheticExecutor()):
        client = TestClient(app)
        capabilities = client.get("/api/v1/superagent/pcap/capabilities")
        overview = client.get("/api/v1/superagent/pcap/overview")
        unauthorized = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "triage_pcap_evidence",
                "authorization_id": "pcap_auth_" + "f" * 32,
            },
        )
        receipt = client.post(
            "/api/v1/superagent/pcap/authorizations",
            json={"confirmed": True, "max_files": 20},
        )
        started = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "triage_pcap_evidence",
                "authorization_id": receipt.json()["authorization_id"],
            },
        )
        polled = client.get(
            "/api/v1/superagent/missions/" + started.json()["mission_id"]
        )
        reused = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "triage_pcap_evidence",
                "authorization_id": receipt.json()["authorization_id"],
            },
        )

    assert capabilities.status_code == 200
    assert capabilities.json() == overview.json()
    assert overview.json() == {
        "enabled": True,
        "pending_file_count": 2318,
        "tool_id": "pcap_batch_triage",
        "max_batch_size": 20,
        "max_trace_events": 12,
        "actors": [
            "coordinator",
            "network_evidence_analyst",
            "knowledge_analyst",
            "response_operator",
        ],
    }
    assert unauthorized.status_code == 403
    assert unauthorized.json()["error"]["code"] == "pcap_authorization_required"
    assert receipt.status_code == 201
    assert set(receipt.json()) == {"authorization_id", "max_files"}
    assert started.status_code == 201
    assert started.json()["objective"] == "triage_pcap_evidence"
    assert polled.status_code == 200
    assert polled.json()["mission_id"] == started.json()["mission_id"]
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == "pcap_authorization_used"
    for response in (
        capabilities,
        overview,
        unauthorized,
        receipt,
        started,
        polled,
        reused,
    ):
        assert _forbidden_hits(response.json()) == []


def test_pcap_polling_works_when_prompt_superagent_is_unavailable() -> None:
    with installed_pcap(SyntheticExecutor()):
        client = TestClient(app)
        receipt = client.post(
            "/api/v1/superagent/pcap/authorizations",
            json={"confirmed": True, "max_files": 1},
        )
        started = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "triage_pcap_evidence",
                "authorization_id": receipt.json()["authorization_id"],
            },
        )
        del app.state.superagent_service
        polled = client.get(
            "/api/v1/superagent/missions/" + started.json()["mission_id"]
        )

    assert polled.status_code == 200
    assert polled.json()["mission_id"] == started.json()["mission_id"]
    assert _forbidden_hits(polled.json()) == []


@pytest.mark.parametrize(
    "payload",
    [
        {"confirmed": False, "max_files": 1},
        {"confirmed": True, "max_files": 0},
        {"confirmed": True, "max_files": 21},
        {"confirmed": True, "max_files": True},
        {"confirmed": True, "max_files": 1.5},
    ],
)
def test_pcap_authorization_requires_confirmation_and_bounded_integer_max_files(
    payload: dict[str, object],
) -> None:
    with installed_pcap(SyntheticExecutor()):
        response = TestClient(app).post(
            "/api/v1/superagent/pcap/authorizations", json=payload
        )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "request_validation_failed",
            "message": "request validation failed",
        }
    }


def test_pcap_expired_authorization_uses_fixed_public_error() -> None:
    clock = [0.0]
    authorizations = PcapAuthorizationStore(
        ttl_seconds=1, clock=lambda: clock[0]
    )
    with installed_pcap(
        SyntheticExecutor(), authorization_store=authorizations
    ):
        client = TestClient(app)
        receipt = client.post(
            "/api/v1/superagent/pcap/authorizations",
            json={"confirmed": True, "max_files": 1},
        )
        clock[0] = 2.0
        expired = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "triage_pcap_evidence",
                "authorization_id": receipt.json()["authorization_id"],
            },
        )

    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "pcap_authorization_expired"
    assert "PRIVATE" not in expired.text


def test_pcap_cancel_acknowledges_before_cleanup_but_prompt_cannot_cancel() -> None:
    executor = BlockingSyntheticExecutor()
    with installed_pcap(executor):
        client = TestClient(app)
        receipt = client.post(
            "/api/v1/superagent/pcap/authorizations",
            json={"confirmed": True, "max_files": 1},
        )
        started = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "triage_pcap_evidence",
                "authorization_id": receipt.json()["authorization_id"],
            },
        )
        assert executor.started.wait(timeout=2)
        cancelled = client.post(
            "/api/v1/superagent/missions/"
            + started.json()["mission_id"]
            + "/cancel"
        )
        running_after_ack = client.get(
            "/api/v1/superagent/missions/" + started.json()["mission_id"]
        )
        executor.release.set()
        deadline = time.monotonic() + 3
        terminal = running_after_ack
        while time.monotonic() < deadline:
            terminal = client.get(
                "/api/v1/superagent/missions/" + started.json()["mission_id"]
            )
            if terminal.json()["status"] == "cancelled":
                break
            time.sleep(0.01)
        prompt = client.post(
            "/api/v1/superagent/missions",
            json={
                "objective": "investigate_and_respond",
                "scenario_kind": "frozen",
                "sample_id": "synthetic_safe",
                "mode": "analysis",
            },
        )
        prompt_cancel = client.post(
            "/api/v1/superagent/missions/"
            + prompt.json()["mission_id"]
            + "/cancel"
        )

    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "running"
    assert running_after_ack.json()["status"] == "running"
    assert terminal.json()["status"] == "cancelled"
    assert _forbidden_hits(cancelled.json()) == []
    assert prompt_cancel.status_code == 409
    assert prompt_cancel.json()["error"]["code"] == "pcap_mission_not_cancellable"
    assert _forbidden_hits(prompt_cancel.json()) == []


def test_pcap_tool_failure_uses_fixed_redacted_error() -> None:
    with installed_pcap(FailingOverviewExecutor()):
        response = TestClient(app).get("/api/v1/superagent/pcap/overview")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "pcap_batch_failed"
    assert "PRIVATE_PCAP_PATH_AND_STDERR" not in response.text
