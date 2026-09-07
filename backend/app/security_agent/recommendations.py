from __future__ import annotations

from app.security_agent.models import (
    AgentCapabilities,
    AgentNextAction,
    AgentSuggestedQuestion,
    AgentTaskSnapshot,
    AgentTaskType,
)


def _question(question_id: str, label: str) -> AgentSuggestedQuestion:
    return AgentSuggestedQuestion(question_id=question_id, label=label, message=label)


def _action(
    action_id: str,
    label: str,
    *,
    required_tool: str | None,
    capabilities: AgentCapabilities,
    action_kind: str = "read_only",
    requires_authorization: bool = False,
) -> AgentNextAction:
    enabled = required_tool is None or required_tool in capabilities.tool_ids
    return AgentNextAction(
        action_id=action_id,
        label=label,
        action_kind=action_kind,
        requires_authorization=requires_authorization,
        enabled=enabled,
        disabled_reason=None if enabled else "当前运行环境未注册所需工具。",
    )


def recommendations_for(
    snapshot: AgentTaskSnapshot,
    capabilities: AgentCapabilities,
) -> tuple[tuple[AgentSuggestedQuestion, ...], tuple[AgentNextAction, ...]]:
    if snapshot.status not in {"completed", "degraded", "failed"}:
        return (), ()

    if snapshot.task_type is AgentTaskType.KNOWLEDGE_EXPLANATION:
        return (
            (
                _question("what_can_you_do", "你还能帮助我做什么？"),
                _question("how_to_start", "怎样开始一次安全调查？"),
            ),
            (),
        )

    if snapshot.task_type is AgentTaskType.PROMPT_INVESTIGATION:
        questions = (
            _question("why_risky", "为什么判断为高风险？"),
            _question("locate_tokens", "异常从哪个 Token 开始？"),
        ) if snapshot.final_status == "risk_found" else (
            _question("why_allowed", "为什么当前可以放行？"),
            _question("decision_limits", "这个结论有什么局限？"),
        )
        actions = [
            _action("suggest_prompt_repair", "生成 Prompt 修复方案", required_tool="analyze_prompt", capabilities=capabilities),
            _action("recheck_prompt", "复检修复后的 Prompt", required_tool="counterfactual_recheck", capabilities=capabilities),
        ]
        if snapshot.report is None:
            actions.append(_action("generate_report", "生成调查报告", required_tool="generate_case_report", capabilities=capabilities))
        return questions, tuple(actions[:4])

    if snapshot.task_type in {
        AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
        AgentTaskType.PCAP_DATASET_INVESTIGATION,
    }:
        questions = (
            _question("which_packets", "哪些 Packet 最可疑？"),
            _question("attack_type", "可能是什么攻击类型？"),
        )
        pcap_tool = "explain_pcap_capture" if snapshot.task_type is AgentTaskType.PCAP_CAPTURE_INVESTIGATION else "detect_pcap_batch"
        actions = [
            _action("inspect_suspicious_packets", "查看可疑 Packet", required_tool=pcap_tool, capabilities=capabilities),
            _action("analyze_attack_chain", "分析攻击链", required_tool=pcap_tool, capabilities=capabilities),
            _action("generate_response_plan", "生成处置方案", required_tool=pcap_tool, capabilities=capabilities),
        ]
        if snapshot.report is None:
            actions.append(_action("generate_report", "生成调查报告", required_tool="generate_case_report", capabilities=capabilities))
        return questions, tuple(actions[:4])

    return (), ()
