from __future__ import annotations

from app.security_agent.models import (
    AgentCapabilities,
    AgentEvidence,
    AgentHypothesis,
    AgentIntent,
    AgentObservation,
    AgentTaskSnapshot,
)
from app.security_agent.planner import HypothesisEvaluator, SecurityAgentPlanner


TOOLS = (
    "analyze_prompt",
    "counterfactual_recheck",
    "inspect_pcap_dataset",
    "detect_pcap_batch",
    "explain_pcap_capture",
    "inspect_encrypted_flow_behavior",
    "retrieve_security_knowledge",
    "generate_case_report",
    "query_simulated_telemetry",
    "verify_response_effect",
)


def capabilities() -> AgentCapabilities:
    return AgentCapabilities(
        planner_mode="deterministic_fallback",
        tool_ids=TOOLS,
        connector_states={
            "pcap_docker": "available",
            "endpoint_demo": "simulated",
        },
    )


def pcap_dataset_intent() -> AgentIntent:
    return AgentIntent(
        kind="investigate_pcap_dataset",
        task_type="pcap_dataset_investigation",
        objective_summary="调查 PCAP 数据集。",
        requires_task=True,
        requires_authorization=True,
    )


def observation(kind: str, *, evidence_refs: tuple[str, ...] = ()) -> AgentObservation:
    return AgentObservation(
        observation_id="obs_01",
        kind=kind,
        status="succeeded",
        summary=f"观察：{kind}",
        observed_at="2026-09-07T08:00:01Z",
        evidence_refs=evidence_refs,
    )


def task_with(
    plan,
    *,
    hypotheses: tuple[AgentHypothesis, ...] = (),
    evidence: tuple[AgentEvidence, ...] = (),
    replans: int = 0,
) -> AgentTaskSnapshot:
    return AgentTaskSnapshot(
        task_id="task_" + "a" * 32,
        version=1,
        task_type="pcap_dataset_investigation",
        status="running",
        title="PCAP 调查",
        objective_summary="调查 PCAP 数据集。",
        created_at="2026-09-07T08:00:00Z",
        updated_at="2026-09-07T08:00:00Z",
        plan=plan,
        hypotheses=hypotheses,
        evidence=evidence,
        replan_count=replans,
    )


def test_pcap_plan_changes_after_encrypted_only_observation() -> None:
    planner = SecurityAgentPlanner()
    plan = planner.create_plan(pcap_dataset_intent(), capabilities())

    revised = planner.replan(task_with(plan), observation("encrypted_only"), capabilities())
    tool_ids = tuple(item.tool_id for item in revised)

    assert "inspect_encrypted_flow_behavior" in tool_ids
    assert "explain_pcap_capture" not in tool_ids


def test_http_candidate_adds_capture_explanation() -> None:
    planner = SecurityAgentPlanner()
    plan = planner.create_plan(pcap_dataset_intent(), capabilities())

    revised = planner.replan(task_with(plan), observation("http_candidate"), capabilities())

    assert "explain_pcap_capture" in tuple(item.tool_id for item in revised)


def test_replanner_honors_two_revision_limit() -> None:
    planner = SecurityAgentPlanner()
    plan = planner.create_plan(pcap_dataset_intent(), capabilities())

    revised = planner.replan(
        task_with(plan, replans=2), observation("encrypted_only"), capabilities()
    )

    assert revised == plan


def test_counter_evidence_lowers_hypothesis_confidence() -> None:
    direct = AgentEvidence(
        evidence_id="ev_real",
        authenticity="real",
        source_type="pcap_detection",
        source_ref="batch_01",
        summary="HTTP 请求呈现注入候选。",
        observed_at="2026-09-07T08:00:00Z",
        uncertainty="需要响应侧验证。",
    )
    hypothesis = AgentHypothesis(
        hypothesis_id="hyp_01",
        title="提示词注入",
        status="investigating",
        confidence=0.82,
        supporting_evidence_refs=("ev_real",),
    )
    snapshot = task_with(( ), hypotheses=(hypothesis,), evidence=(direct,))

    updated = HypothesisEvaluator().evaluate(
        snapshot, observation("normal_response_ratio", evidence_refs=("ev_counter",))
    )

    assert updated.hypotheses[0].confidence < 0.82
    assert updated.hypotheses[0].opposing_evidence_refs == ("ev_counter",)


def test_hypothesis_cannot_be_supported_without_direct_real_evidence() -> None:
    derived = AgentEvidence(
        evidence_id="ev_derived",
        authenticity="derived",
        source_type="explanation",
        source_ref="report_01",
        summary="派生解释。",
        observed_at="2026-09-07T08:00:00Z",
        uncertainty="不是直接检测证据。",
    )
    hypothesis = AgentHypothesis(
        hypothesis_id="hyp_01",
        title="提示词注入",
        status="investigating",
        confidence=0.7,
    )
    snapshot = task_with((), hypotheses=(hypothesis,), evidence=(derived,))

    updated = HypothesisEvaluator().evaluate(
        snapshot, observation("direct_attack_signal", evidence_refs=("ev_derived",))
    )

    assert updated.hypotheses[0].status != "supported"

