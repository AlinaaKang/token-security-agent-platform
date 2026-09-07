from __future__ import annotations

from app.security_agent.models import AgentCapabilities, AgentTaskSnapshot
from app.security_agent.recommendations import recommendations_for


def _snapshot(*, task_type: str, final_status: str | None, evidence: bool = True, report: bool = False) -> AgentTaskSnapshot:
    payload: dict[str, object] = {
        "task_id": "task_0123456789abcdef0123456789abcdef",
        "version": 1,
        "task_type": task_type,
        "status": "completed",
        "title": "安全调查",
        "objective_summary": "调查公开证据。",
        "created_at": "2026-09-07T08:00:00Z",
        "updated_at": "2026-09-07T08:00:01Z",
        "evidence": [{
            "evidence_id": "ev_01",
            "authenticity": "real",
            "source_type": "detector",
            "source_ref": "case_01",
            "summary": "发现公开异常证据。",
            "observed_at": "2026-09-07T08:00:01Z",
            "uncertainty": "尚未证明攻击成功。",
        }] if evidence else [],
        "final_status": final_status,
        "report": {
            "report_id": "report_01",
            "title": "安全调查报告",
            "status": "ready",
            "artifact_ref": "report_01.md",
            "evidence_refs": ["ev_01"],
            "generated_at": "2026-09-07T08:00:02Z",
        } if report else None,
    }
    return AgentTaskSnapshot.model_validate(payload)


def _capabilities(*tool_ids: str) -> AgentCapabilities:
    return AgentCapabilities(
        planner_mode="deterministic_fallback",
        tool_ids=tool_ids,
        connector_states={"prompt_runtime": "available", "pcap_docker": "available"},
    )


def test_prompt_risk_recommends_explanation_repair_recheck_and_report() -> None:
    questions, actions = recommendations_for(
        _snapshot(task_type="prompt_investigation", final_status="risk_found"),
        _capabilities("analyze_prompt", "counterfactual_recheck", "generate_case_report"),
    )

    assert [item.question_id for item in questions] == ["why_risky", "locate_tokens"]
    assert [item.action_id for item in actions] == [
        "suggest_prompt_repair", "recheck_prompt", "generate_report",
    ]


def test_pcap_risk_recommends_packet_attack_chain_response_and_report() -> None:
    questions, actions = recommendations_for(
        _snapshot(task_type="pcap_capture_investigation", final_status="risk_found"),
        _capabilities("explain_pcap_capture", "generate_case_report"),
    )

    assert [item.question_id for item in questions] == ["which_packets", "attack_type"]
    assert [item.action_id for item in actions] == [
        "inspect_suspicious_packets", "analyze_attack_chain",
        "generate_response_plan", "generate_report",
    ]


def test_unavailable_tools_are_exposed_as_disabled_with_a_reason() -> None:
    _, actions = recommendations_for(
        _snapshot(task_type="pcap_capture_investigation", final_status="risk_found"),
        _capabilities(),
    )

    assert actions
    assert all(not item.enabled for item in actions)
    assert all(item.disabled_reason for item in actions)


def test_existing_report_removes_duplicate_report_action() -> None:
    _, actions = recommendations_for(
        _snapshot(task_type="prompt_investigation", final_status="risk_found", report=True),
        _capabilities("analyze_prompt", "counterfactual_recheck", "generate_case_report"),
    )

    assert "generate_report" not in {item.action_id for item in actions}


def test_conversational_task_offers_questions_without_security_actions() -> None:
    questions, actions = recommendations_for(
        _snapshot(task_type="knowledge_explanation", final_status=None, evidence=False),
        _capabilities(),
    )

    assert 1 <= len(questions) <= 4
    assert actions == ()
