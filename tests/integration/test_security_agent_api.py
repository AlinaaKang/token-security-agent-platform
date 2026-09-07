from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.security_agent.coordinator import SecurityAgentCoordinator
from app.security_agent.feedback import AnalystFeedbackService
from app.security_agent.models import AgentCapabilities
from app.security_agent.store import SecurityAgentStore
from app.security_agent.tools import build_registry


def _handler(tool_id: str):
    if tool_id == "query_simulated_telemetry":
        return lambda _arguments: {
            "objective": tool_id,
            "status": "completed",
            "observation_kind": "direct_attack_signal",
            "summary": {
                "analyzed_count": 1,
                "failed_count": 0,
                "evidence": [{
                    "evidence_id": "ev_simulated_endpoint",
                    "detector": "endpoint_demo",
                    "attack_candidate": "endpoint_process_anomaly",
                    "confidence": 0.76,
                }],
            },
        }
    if tool_id == "verify_response_effect":
        return lambda _arguments: {
            "objective": tool_id,
            "status": "completed",
            "observation_kind": "response_verified",
            "summary": "内部仿真处置效果已经独立复核。",
        }
    return lambda _arguments: {
        "objective": tool_id,
        "status": "completed",
        "summary": {"analyzed_count": 1, "failed_count": 0, "evidence": []},
    }


@contextmanager
def installed(tmp_path: Path):
    handlers = {tool_id: _handler(tool_id) for tool_id in build_registry({}).ids()}
    registry = build_registry(handlers)
    capabilities = AgentCapabilities(
        planner_mode="deterministic_fallback",
        tool_ids=registry.ids(),
        connector_states={"pcap_docker": "available", "endpoint_demo": "simulated"},
    )
    coordinator = SecurityAgentCoordinator(
        store=SecurityAgentStore(tmp_path / "agent.sqlite3"),
        registry=registry,
        capabilities=capabilities,
    )
    previous = getattr(app.state, "security_agent_coordinator", None)
    previous_feedback = getattr(app.state, "security_agent_feedback", None)
    app.state.security_agent_coordinator = coordinator
    feedback = AnalystFeedbackService(
        tmp_path / "feedback.sqlite3", detector_identity=lambda: "frozen-test-v1"
    )
    app.state.security_agent_feedback = feedback
    try:
        yield TestClient(app), coordinator
    finally:
        feedback.close()
        coordinator.close()
        if previous is None:
            if hasattr(app.state, "security_agent_coordinator"):
                delattr(app.state, "security_agent_coordinator")
        else:
            app.state.security_agent_coordinator = previous
        if previous_feedback is None:
            if hasattr(app.state, "security_agent_feedback"):
                delattr(app.state, "security_agent_feedback")
        else:
            app.state.security_agent_feedback = previous_feedback


def test_capabilities_and_identity_conversation(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        response = client.get("/api/v1/agent/capabilities")
        created = client.post("/api/v1/agent/tasks", json={"message": "你叫什么名字"})

    assert response.status_code == 200
    assert response.json()["max_plan_steps"] == 12
    assert created.status_code == 201
    assert created.json()["status"] == "completed"


def test_task_switch_does_not_cancel_background_execution(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        created = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        client.get("/api/v1/agent/tasks")
        restored = client.get(f"/api/v1/agent/tasks/{created['task_id']}").json()

    assert restored["status"] != "cancelled"


def test_authorization_scope_mismatch_has_public_error(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        response = client.post(
            f"/api/v1/agent/tasks/{task['task_id']}/authorizations",
            json={"confirmed": True, "scopes": ["prompt:analyze"]},
        )

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "agent_authorization_scope_mismatch",
            "message": "authorization scope does not match the task",
        }
    }


def test_sse_replays_only_events_after_last_event_id(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        response = client.get(
            f"/api/v1/agent/tasks/{task['task_id']}/events",
            headers={"Last-Event-ID": "1"},
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "id: 1\n" not in response.text
    assert "id: 2\n" in response.text


def test_explicit_cancel_and_missing_task_errors(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        cancelled = client.post(f"/api/v1/agent/tasks/{task['task_id']}/cancel")
        missing = client.get("/api/v1/agent/tasks/task_missing")

    assert cancelled.json()["status"] == "cancelled"
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "agent_task_not_found"


def test_task_listing_and_follow_up_message(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        followed = client.post(
            f"/api/v1/agent/tasks/{task['task_id']}/messages",
            json={"message": "packet 4-4 是什么"},
        )
        listing = client.get("/api/v1/agent/tasks?limit=20&offset=0")

    assert followed.status_code == 200
    assert "数据包范围" in followed.json()["messages"][-1]["content"]
    assert listing.json()["items"][0]["task_id"] == task["task_id"]


def test_resource_catalog_and_append_only_feedback_api(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        playbooks = client.get("/api/v1/agent/playbooks")
        connectors = client.get("/api/v1/agent/connectors")
        feedback = client.post(
            f"/api/v1/agent/tasks/{task['task_id']}/feedback",
            json={
                "verdict": "confirmed",
                "reason_code": "analyst_confirmed",
                "evidence_refs": [],
            },
        )

    assert playbooks.status_code == 200
    assert playbooks.json()["version"] == "1.0.0"
    assert any(item["playbook_id"] == "pcap_dataset_v1" for item in playbooks.json()["playbooks"])
    assert connectors.status_code == 200
    assert any(item["authenticity"] == "simulated" for item in connectors.json())
    assert feedback.status_code == 201
    assert feedback.json()["task_id"] == task["task_id"]


def test_cross_domain_demo_exposes_observation_replan_counterevidence_and_verification(
    tmp_path,
) -> None:
    with installed(tmp_path) as (client, coordinator):
        created = client.post(
            "/api/v1/agent/tasks", json={"message": "运行跨域攻防演示"}
        ).json()
        coordinator.authorize(
            created["task_id"], ("demo:use", "response:execute")
        )
        finished = coordinator.run_until_blocked(created["task_id"])

    phases = [event.phase for event in finished.events]
    assert "plan" in phases
    assert "observe" in phases
    assert "replan" in phases
    assert phases[-1] == "complete"
    assert any(item.authenticity == "simulated" for item in finished.evidence)
    assert any(item.authenticity == "simulated" for item in finished.timeline)
    assert len(finished.hypotheses) >= 2
    assert any(item.opposing_evidence_refs for item in finished.hypotheses)
    assert any(item.kind == "response_verified" for item in finished.observations)
    assert all(item.status in {"succeeded", "failed", "skipped"} for item in finished.plan)
