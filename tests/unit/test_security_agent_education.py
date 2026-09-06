from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.security_agent.education import SecurityEducationService
from app.security_agent.intent import parse_intent
from app.security_agent.models import AgentEvidence


def service() -> SecurityEducationService:
    return SecurityEducationService(
        clock=lambda: datetime(2026, 9, 7, 8, 0, tzinfo=UTC)
    )


def current_evidence() -> AgentEvidence:
    return AgentEvidence(
        evidence_id="ev_pcap_01",
        authenticity="real",
        source_type="pcap_detection",
        source_ref="batch_01",
        tool_id="detect_pcap_batch",
        summary="发现重复内部地址探测模式。",
        observed_at="2026-09-07T08:00:00Z",
        uncertainty="只能证明存在探测特征，不能证明攻击成功。",
    )


def test_identity_answer_does_not_require_case_evidence() -> None:
    answer = service().answer(parse_intent("你叫什么名字", None))

    assert "Token Security 安全智能体" in answer.content
    assert answer.evidence_scope == "general"
    assert answer.evidence_refs == ()


def test_capabilities_answer_states_real_and_simulated_boundaries() -> None:
    answer = service().answer(parse_intent("你能做什么", None))

    assert "Prompt" in answer.content
    assert "PCAP" in answer.content
    assert "仿真" in answer.content
    assert "真实 EDR" in answer.content


def test_attack_education_is_grounded_in_an_approved_knowledge_reference() -> None:
    answer = service().answer(parse_intent("什么是提示词注入", None))

    assert "提示词注入" in answer.content
    assert "knowledge:owasp-llm01-prompt-injection" in answer.evidence_refs
    assert answer.evidence_scope == "general"


def test_pcap_explanation_does_not_claim_attack_success() -> None:
    answer = service().answer(parse_intent("packet 4-4 是什么", None), [current_evidence()])

    assert "数据包范围" in answer.content
    assert "不能单独证明攻击成功" in answer.content
    assert answer.evidence_scope == "current_case"
    assert answer.evidence_refs == ("ev_pcap_01",)


def test_current_evidence_answer_preserves_uncertainty() -> None:
    answer = service().answer(
        parse_intent("为什么这个是高风险", None), [current_evidence()]
    )

    assert "发现重复内部地址探测模式" in answer.content
    assert "不能证明攻击成功" in answer.content


def test_out_of_scope_answer_refuses_complex_unrelated_work() -> None:
    answer = service().answer(parse_intent("帮我写一个财务报表", None))

    assert "安全调查" in answer.content
    assert "无法代替" in answer.content


def test_education_rejects_non_conversational_side_effect_intent() -> None:
    with pytest.raises(ValueError, match="not an educational intent"):
        service().answer(parse_intent("检测这批 PCAP", None))

