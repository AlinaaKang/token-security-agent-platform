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
from tests.unit.test_security_agent_pcap_import import _mission


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


def test_task_creation_persists_pcap_workspace_for_general_questions(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        created = client.post(
            "/api/v1/agent/tasks",
            json={"message": "你好", "workspace_mode": "pcap"},
        )
        restored = client.get(
            f"/api/v1/agent/tasks/{created.json()['task_id']}"
        )

    assert created.status_code == 201
    assert created.json()["workspace_mode"] == "pcap"
    assert restored.json()["workspace_mode"] == "pcap"


def test_pcap_task_accepts_free_form_contextual_questions(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        created = client.post(
            "/api/v1/agent/tasks",
            json={"message": "你好", "workspace_mode": "pcap"},
        ).json()
        response = client.post(
            f"/api/v1/agent/tasks/{created['task_id']}/messages",
            json={"message": "可能是什么攻击类型？"},
        )

    assert response.status_code == 200
    assert "属于当前 PCAP 调查范围" in response.json()["messages"][-1]["content"]
    assert "超出" not in response.json()["messages"][-1]["content"]


def test_public_pcap_result_import_is_idempotent_and_conversational(tmp_path) -> None:
    public_result = _mission().model_dump(mode="json")
    with installed(tmp_path) as (client, _coordinator):
        first = client.post("/api/v1/agent/tasks/import-pcap", json=public_result)
        second = client.post("/api/v1/agent/tasks/import-pcap", json=public_result)

    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["task_id"] == first.json()["task_id"]
    assert second.json()["task_type"] == "pcap_capture_investigation"
    assert second.json()["next_actions"]
    encoded = second.text.lower()
    for forbidden in ("filename", "file_path", "payload", "ip_address", '"port"'):
        assert forbidden not in encoded


def test_public_pcap_result_import_appends_to_existing_pcap_conversation(tmp_path) -> None:
    public_result = _mission().model_dump(mode="json")
    with installed(tmp_path) as (client, _coordinator):
        created = client.post(
            "/api/v1/agent/tasks",
            json={"message": "你好", "workspace_mode": "pcap"},
        ).json()
        first = client.post(
            f"/api/v1/agent/tasks/import-pcap?task_id={created['task_id']}",
            json=public_result,
        )
        second = client.post(
            f"/api/v1/agent/tasks/import-pcap?task_id={created['task_id']}",
            json=public_result,
        )
        listed = client.get("/api/v1/agent/tasks").json()["items"]

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["task_id"] == created["task_id"]
    assert second.json()["task_id"] == created["task_id"]
    assert first.json()["messages"][0] == created["messages"][0]
    assert len(first.json()["messages"]) > len(created["messages"])
    assert second.json()["messages"] == first.json()["messages"]
    assert second.json()["evidence"] == first.json()["evidence"]
    assert first.json()["task_type"] == "pcap_capture_investigation"
    assert len(listed) == 1


def test_public_pcap_result_import_rejects_a_prompt_conversation_target(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        created = client.post(
            "/api/v1/agent/tasks",
            json={"message": "你好", "workspace_mode": "prompt"},
        ).json()
        response = client.post(
            f"/api/v1/agent/tasks/import-pcap?task_id={created['task_id']}",
            json=_mission().model_dump(mode="json"),
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "pcap_target_workspace_mismatch"


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


def test_task_can_be_deleted_and_is_no_longer_listed(tmp_path) -> None:
    with installed(tmp_path) as (client, _coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这段 Prompt 是否包含越狱风险"}
        ).json()
        deleted = client.delete(f"/api/v1/agent/tasks/{task['task_id']}")
        restored = client.get(f"/api/v1/agent/tasks/{task['task_id']}")
        listing = client.get("/api/v1/agent/tasks").json()

    assert "越狱风险" in task["title"]
    assert deleted.status_code == 204
    assert restored.status_code == 404
    assert all(item["task_id"] != task["task_id"] for item in listing["items"])


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
    assert "当前 PCAP 调查范围" in followed.json()["messages"][-1]["content"]
    assert "还没有可引用" in followed.json()["messages"][-1]["content"]
    assert listing.json()["items"][0]["task_id"] == task["task_id"]


def test_recommended_report_action_executes_and_rejects_stale_actions(tmp_path) -> None:
    with installed(tmp_path) as (client, coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        coordinator.authorize(task["task_id"], ("pcap:read",))
        coordinator.run_until_blocked(task["task_id"])

        generated = client.post(
            f"/api/v1/agent/tasks/{task['task_id']}/actions",
            json={"action_id": "generate_report"},
        )
        stale = client.post(
            f"/api/v1/agent/tasks/{task['task_id']}/actions",
            json={"action_id": "generate_report"},
        )

    assert generated.status_code == 200
    assert generated.json()["report"] is not None
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "agent_action_not_available"


def test_resource_catalog_and_append_only_feedback_api(tmp_path) -> None:
    with installed(tmp_path) as (client, coordinator):
        task = client.post(
            "/api/v1/agent/tasks", json={"message": "检测这批 PCAP"}
        ).json()
        coordinator.authorize(task["task_id"], ("pcap:read",))
        coordinator.run_until_blocked(task["task_id"])
        client.post(
            f"/api/v1/agent/tasks/{task['task_id']}/actions",
            json={"action_id": "generate_report"},
        )
        playbooks = client.get("/api/v1/agent/playbooks")
        connectors = client.get("/api/v1/agent/connectors")
        knowledge = client.get("/api/v1/agent/knowledge")
        reports = client.get("/api/v1/agent/reports")
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
    assert knowledge.status_code == 200
    assert knowledge.json()["snapshot_version"] == "official-v2"
    assert knowledge.json()["card_count"] >= 1
    assert any(item["publisher"] == "owasp" for item in knowledge.json()["items"])
    assert reports.status_code == 200
    assert reports.json()["items"][0]["task_id"] == task["task_id"]
    assert reports.json()["items"][0]["download_url"].startswith("/api/v1/agent/reports/")
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
