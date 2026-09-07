from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from app.security_agent.models import (
    AgentCapabilities,
    AgentConfidenceChange,
    AgentEvidence,
    AgentHypothesis,
    AgentNextAction,
    AgentPlanStep,
    AgentSuggestedQuestion,
    AgentTaskSnapshot,
    EvidenceAuthenticity,
)


def evidence_payload(
    evidence_id: str,
    authenticity: str,
    *,
    summary: str = "公开、脱敏的调查证据。",
) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "authenticity": authenticity,
        "source_type": "pcap_detection",
        "source_ref": "batch_01",
        "tool_id": "detect_pcap_batch",
        "summary": summary,
        "observed_at": "2026-09-07T08:00:00Z",
        "uncertainty": "仅代表当前授权范围。",
    }


def hypothesis_payload(
    *, confidence_changes: list[dict[str, object]] | None = None
) -> dict[str, object]:
    return {
        "hypothesis_id": "hyp_01",
        "title": "可能存在提示词注入侦察",
        "status": "investigating",
        "confidence": 0.8,
        "supporting_evidence_refs": ["ev_real"],
        "opposing_evidence_refs": ["ev_derived"],
        "confidence_changes": confidence_changes
        if confidence_changes is not None
        else [
            {
                "before": 0.25,
                "after": 0.8,
                "evidence_refs": ["ev_real"],
                "reason": "真实检测证据提高了该假设的可信度。",
                "changed_at": "2026-09-07T08:00:01Z",
            }
        ],
        "limitations": ["尚未验证攻击是否成功。"],
    }


def snapshot_payload() -> dict[str, object]:
    return {
        "task_id": "task_0123456789abcdef0123456789abcdef",
        "version": 1,
        "task_type": "pcap_dataset_investigation",
        "status": "running",
        "title": "调查授权 PCAP 数据集",
        "objective_summary": "识别异常候选并生成可审计结论。",
        "created_at": "2026-09-07T08:00:00Z",
        "updated_at": "2026-09-07T08:00:01Z",
        "messages": [
            {
                "message_id": "msg_01",
                "role": "agent",
                "kind": "status",
                "content": "正在分析已授权的数据集。",
                "created_at": "2026-09-07T08:00:00Z",
                "evidence_scope": "current_case",
                "evidence_refs": [],
            }
        ],
        "plan": [
            {
                "step_id": "step_01",
                "tool_id": "detect_pcap_batch",
                "status": "running",
                "requires_authorization": True,
                "summary": "检测下一批 PCAP 文件。",
                "depends_on": [],
            }
        ],
        "observations": [],
        "evidence": [
            evidence_payload("ev_real", "real"),
            evidence_payload("ev_simulated", "simulated"),
            evidence_payload("ev_derived", "derived"),
        ],
        "hypotheses": [hypothesis_payload()],
        "timeline": [],
        "conflicts": [],
        "events": [],
        "replan_count": 0,
        "authorization_scopes": ["pcap:dataset:batch"],
        "final_status": None,
        "report": None,
        "limitations": ["无法解密加密负载。"],
    }


def test_agent_snapshot_separates_real_simulated_and_derived_evidence() -> None:
    snapshot = AgentTaskSnapshot.model_validate(snapshot_payload())

    assert [item.authenticity for item in snapshot.evidence] == [
        EvidenceAuthenticity.REAL,
        EvidenceAuthenticity.SIMULATED,
        EvidenceAuthenticity.DERIVED,
    ]


@pytest.mark.parametrize(
    "private_key",
    [
        "prompt",
        "suffix",
        "payload",
        "file_path",
        "token_ids",
        "raw_output",
        "hidden_reasoning",
    ],
)
def test_agent_public_models_reject_private_keys(private_key: str) -> None:
    payload = snapshot_payload()
    payload[private_key] = "PRIVATE_SENTINEL"

    with pytest.raises(ValidationError):
        AgentTaskSnapshot.model_validate(payload)


def test_agent_public_models_reject_nested_private_keys() -> None:
    payload = snapshot_payload()
    payload["evidence"][0]["metadata"] = {"file_path": "PRIVATE_SENTINEL"}  # type: ignore[index]

    with pytest.raises(ValidationError, match="forbidden public field"):
        AgentTaskSnapshot.model_validate(payload)


def test_structured_cot_requires_evidence_for_confidence_changes() -> None:
    payload = hypothesis_payload(
        confidence_changes=[
            {
                "before": 0.25,
                "after": 0.8,
                "evidence_refs": [],
                "reason": "没有证据的置信度变化不应公开。",
                "changed_at": "2026-09-07T08:00:01Z",
            }
        ]
    )

    with pytest.raises(ValidationError):
        AgentHypothesis.model_validate(payload)


def test_confidence_change_accepts_support_or_counter_evidence() -> None:
    change = AgentConfidenceChange.model_validate(
        {
            "before": 0.82,
            "after": 0.55,
            "evidence_refs": ["ev_counter"],
            "reason": "响应比例正常，形成反证。",
            "changed_at": "2026-09-07T08:00:02Z",
        }
    )

    assert change.after == 0.55
    assert change.evidence_refs == ("ev_counter",)


def test_public_models_are_frozen_and_forbid_unknown_fields() -> None:
    evidence = AgentEvidence.model_validate(evidence_payload("ev_real", "real"))
    step = AgentPlanStep.model_validate(snapshot_payload()["plan"][0])  # type: ignore[index]

    with pytest.raises(ValidationError):
        evidence.summary = "被篡改"
    with pytest.raises(ValidationError):
        AgentPlanStep.model_validate({**step.model_dump(), "shell_command": "whoami"})


def test_snapshot_enforces_public_collection_limits() -> None:
    payload = snapshot_payload()
    message = deepcopy(payload["messages"][0])  # type: ignore[index]
    payload["messages"] = [
        {**message, "message_id": f"msg_{index:03d}"} for index in range(101)
    ]

    with pytest.raises(ValidationError):
        AgentTaskSnapshot.model_validate(payload)


def test_capabilities_publish_bounded_runtime_limits() -> None:
    capabilities = AgentCapabilities.model_validate(
        {
            "planner_mode": "deterministic_fallback",
            "tool_ids": ["detect_pcap_batch", "generate_report"],
            "connector_states": {
                "pcap_docker": "available",
                "endpoint_demo": "simulated",
            },
            "max_plan_steps": 12,
            "max_concurrent_tools": 3,
            "max_replans": 2,
            "max_active_hypotheses": 5,
            "pcap_batch_size": 20,
        }
    )

    assert capabilities.max_plan_steps == 12
    assert capabilities.pcap_batch_size == 20


def test_recommendation_models_are_strict_and_bounded() -> None:
    question = AgentSuggestedQuestion(
        question_id="why_risky",
        label="为什么判断为高风险？",
        message="为什么判断为高风险？",
    )
    action = AgentNextAction(
        action_id="generate_report",
        label="生成调查报告",
        action_kind="read_only",
    )

    payload = snapshot_payload()
    payload["suggested_questions"] = [question.model_dump()] * 5
    payload["next_actions"] = [action.model_dump()]
    with pytest.raises(ValidationError):
        AgentTaskSnapshot.model_validate(payload)

    with pytest.raises(ValidationError):
        AgentNextAction.model_validate({**action.model_dump(), "action_id": "shell_exec"})
