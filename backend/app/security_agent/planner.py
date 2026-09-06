from __future__ import annotations

from dataclasses import dataclass

from app.security_agent.models import (
    AgentCapabilities,
    AgentConfidenceChange,
    AgentHypothesis,
    AgentIntent,
    AgentObservation,
    AgentPlanStep,
    AgentTaskSnapshot,
    AgentTaskType,
    EvidenceAuthenticity,
)


@dataclass(frozen=True)
class _StepTemplate:
    tool_id: str
    summary: str
    authorization: bool = False


_PLAN_TEMPLATES: dict[AgentTaskType, tuple[_StepTemplate, ...]] = {
    AgentTaskType.KNOWLEDGE_EXPLANATION: (
        _StepTemplate("retrieve_security_knowledge", "检索批准的离线安全知识。"),
        _StepTemplate("explain_attack", "生成带证据边界的攻击科普。"),
    ),
    AgentTaskType.PROMPT_INVESTIGATION: (
        _StepTemplate("analyze_prompt", "运行真实 Prompt 与 Token 检测。", True),
        _StepTemplate("counterfactual_recheck", "执行截断反事实复核。", True),
        _StepTemplate("retrieve_security_knowledge", "检索相关安全知识。"),
        _StepTemplate("generate_case_report", "生成引用式案件报告。"),
    ),
    AgentTaskType.PCAP_DATASET_INVESTIGATION: (
        _StepTemplate("inspect_pcap_dataset", "清点和画像授权 PCAP 数据集。", True),
        _StepTemplate("detect_pcap_batch", "分批检测异常、失败和未命中。", True),
        _StepTemplate("retrieve_security_knowledge", "检索候选攻击知识。"),
        _StepTemplate("generate_case_report", "聚合证据并生成报告。"),
    ),
    AgentTaskType.PCAP_CAPTURE_INVESTIGATION: (
        _StepTemplate("detect_pcap_batch", "隔离检测授权 PCAP 文件。", True),
        _StepTemplate("explain_pcap_capture", "解释协议、包区间和目的候选。", True),
        _StepTemplate("generate_case_report", "生成单文件调查报告。"),
    ),
    AgentTaskType.CROSS_DOMAIN_CASE: (
        _StepTemplate("query_simulated_telemetry", "读取明确标注的内置仿真遥测。", True),
        _StepTemplate("retrieve_security_knowledge", "检索跨域攻击知识。"),
        _StepTemplate("simulate_response_options", "比较可逆处置方案的预期影响。"),
        _StepTemplate("preview_response_action", "预览平台内部处置动作。"),
        _StepTemplate("execute_internal_action", "执行已授权的平台内部动作。", True),
        _StepTemplate("verify_response_effect", "独立验证处置动作是否生效。"),
        _StepTemplate("generate_case_report", "生成跨源案件报告。"),
    ),
    AgentTaskType.REPORT_GENERATION: (
        _StepTemplate("generate_case_report", "基于当前公开证据生成报告。"),
    ),
}


class SecurityAgentPlanner:
    def create_plan(
        self, intent: AgentIntent, capabilities: AgentCapabilities
    ) -> tuple[AgentPlanStep, ...]:
        if intent.task_type is None:
            return ()
        templates = _PLAN_TEMPLATES[intent.task_type]
        available = set(capabilities.tool_ids)
        return _build_steps(tuple(item for item in templates if item.tool_id in available))

    def replan(
        self,
        snapshot: AgentTaskSnapshot,
        observation: AgentObservation,
        capabilities: AgentCapabilities,
    ) -> tuple[AgentPlanStep, ...]:
        if snapshot.replan_count >= capabilities.max_replans:
            return snapshot.plan
        templates = [
            _StepTemplate(step.tool_id, step.summary, step.requires_authorization)
            for step in snapshot.plan
            if step.tool_id is not None and step.status in {"waiting", "running"}
        ]
        trigger = observation.kind
        if trigger == "encrypted_only":
            templates = [item for item in templates if item.tool_id != "explain_pcap_capture"]
            _insert_before_report(
                templates,
                _StepTemplate(
                    "inspect_encrypted_flow_behavior",
                    "改用 TLS、DNS 与流量行为证据分析加密流量。",
                    True,
                ),
            )
        elif trigger == "http_candidate":
            _insert_before_report(
                templates,
                _StepTemplate(
                    "explain_pcap_capture",
                    "定位 HTTP 候选并分析攻击目的与响应关联。",
                    True,
                ),
            )
        elif trigger == "parse_failure":
            _insert_before_report(
                templates,
                _StepTemplate(
                    "inspect_pcap_dataset",
                    "使用兼容画像路径复核解析失败文件。",
                    True,
                ),
            )
        elif trigger == "prompt_evidence_conflict":
            _insert_before_report(
                templates,
                _StepTemplate(
                    "counterfactual_recheck",
                    "针对语义与 Token 冲突执行反事实复核。",
                    True,
                ),
            )
        elif trigger == "knowledge_shortage":
            templates = [
                item for item in templates if item.tool_id != "retrieve_security_knowledge"
            ]
        elif trigger == "temporary_tool_failure":
            templates = [
                _StepTemplate(item.tool_id, f"重试：{item.summary}", item.authorization)
                if item.tool_id == observation.tool_id
                else item
                for item in templates
            ]
        else:
            return snapshot.plan
        available = set(capabilities.tool_ids)
        bounded = tuple(item for item in templates if item.tool_id in available)
        return _build_steps(bounded[: capabilities.max_plan_steps])


class HypothesisEvaluator:
    _WEIGHTS = {
        "direct_attack_signal": 0.2,
        "http_candidate": 0.12,
        "normal_response_ratio": -0.27,
        "benign_business_pattern": -0.35,
    }

    def evaluate(
        self, snapshot: AgentTaskSnapshot, observation: AgentObservation
    ) -> AgentTaskSnapshot:
        weight = self._WEIGHTS.get(observation.kind)
        if weight is None or not observation.evidence_refs:
            return snapshot
        evidence_by_id = {item.evidence_id: item for item in snapshot.evidence}
        has_direct_real = any(
            evidence_by_id.get(reference) is not None
            and evidence_by_id[reference].authenticity is EvidenceAuthenticity.REAL
            for reference in observation.evidence_refs
        )
        updated: list[AgentHypothesis] = []
        for hypothesis in snapshot.hypotheses:
            confidence = min(1.0, max(0.0, hypothesis.confidence + weight))
            supporting = hypothesis.supporting_evidence_refs
            opposing = hypothesis.opposing_evidence_refs
            if weight > 0:
                supporting = _unique(supporting + observation.evidence_refs)
            else:
                opposing = _unique(opposing + observation.evidence_refs)
            status = hypothesis.status
            if confidence >= 0.8 and has_direct_real:
                status = "supported"
            elif confidence < 0.35:
                status = "weakened"
            change = AgentConfidenceChange(
                before=hypothesis.confidence,
                after=confidence,
                evidence_refs=observation.evidence_refs,
                reason=(
                    "新增支持证据提高了候选假设置信度。"
                    if weight > 0
                    else "新增反对证据降低了候选假设置信度。"
                ),
                changed_at=observation.observed_at,
            )
            updated.append(
                hypothesis.model_copy(
                    update={
                        "confidence": confidence,
                        "status": status,
                        "supporting_evidence_refs": supporting,
                        "opposing_evidence_refs": opposing,
                        "confidence_changes": hypothesis.confidence_changes + (change,),
                    }
                )
            )
        return snapshot.model_copy(update={"hypotheses": tuple(updated)})


def _build_steps(templates: tuple[_StepTemplate, ...]) -> tuple[AgentPlanStep, ...]:
    steps: list[AgentPlanStep] = []
    for index, item in enumerate(templates, start=1):
        steps.append(
            AgentPlanStep(
                step_id=f"step_{index:02d}",
                tool_id=item.tool_id,
                status="waiting",
                requires_authorization=item.authorization,
                summary=item.summary,
                depends_on=(f"step_{index - 1:02d}",) if index > 1 else (),
            )
        )
    return tuple(steps)


def _insert_before_report(templates: list[_StepTemplate], item: _StepTemplate) -> None:
    if any(existing.tool_id == item.tool_id for existing in templates):
        return
    index = next(
        (i for i, existing in enumerate(templates) if existing.tool_id == "generate_case_report"),
        len(templates),
    )
    templates.insert(index, item)


def _unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
