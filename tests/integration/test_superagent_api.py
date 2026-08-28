from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from fastapi.testclient import TestClient

from app.lab.models import FORBIDDEN_PUBLIC_KEYS
from app.main import app
from app.schemas import Decision
from app.superagent.service import SuperAgentService
from app.superagent.store import SuperAgentMissionStore
from tests.unit.test_superagent_service import FakeLabService


def _forbidden_hits(value: object) -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_PUBLIC_KEYS:
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
