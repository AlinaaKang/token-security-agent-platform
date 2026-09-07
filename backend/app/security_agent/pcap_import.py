from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.pcap.detection_models import PcapDetectionMissionResult
from app.security_agent.models import (
    AgentEvidence,
    AgentHypothesis,
    AgentObservation,
    AgentPlanStep,
    AgentTimelineEvent,
)


_ATTACK_LABELS = {
    "sql_injection": "SQL 注入",
    "command_injection": "命令注入",
    "path_traversal": "路径遍历",
    "web_injection": "Web 注入",
    "none": "未分类异常",
}


class AgentPcapImport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_ref: str
    degraded: bool
    final_status: Literal["risk_found", "inconclusive"]
    result_text: str
    plan: tuple[AgentPlanStep, ...]
    observations: tuple[AgentObservation, ...]
    evidence: tuple[AgentEvidence, ...]
    hypotheses: tuple[AgentHypothesis, ...]
    timeline: tuple[AgentTimelineEvent, ...]
    limitations: tuple[str, ...]


def import_pcap_detection(result: PcapDetectionMissionResult) -> AgentPcapImport:
    if result.status not in {"completed", "degraded"} or result.summary is None:
        raise ValueError("pcap_detection_not_terminal")

    summary = result.summary
    source_ref = f"pcap-detection:{result.detection_id}"
    evidence = tuple(_evidence(item, result.created_at, source_ref) for item in summary.evidence)
    evidence_refs = tuple(item.evidence_id for item in evidence)
    degraded = result.status == "degraded" or summary.failed_count > 0
    final_status: Literal["risk_found", "inconclusive"] = (
        "risk_found" if evidence else "inconclusive"
    )
    if evidence:
        result_text = (
            f"PCAP 调查完成：分析 {summary.analyzed_count} 个样本，定位到 "
            f"{len(evidence)} 处异常候选。异常候选不等于攻击已经成功。"
        )
    else:
        result_text = (
            f"PCAP 调查完成：分析 {summary.analyzed_count} 个样本，当前规则未定位到"
            "可复核异常；未命中不等于流量全部安全。"
        )
    if degraded:
        result_text += f" 其中 {summary.failed_count} 个样本未成功完成分析。"

    limitations = ["仅保存脱敏统计、Packet 范围和检测候选，不包含原始载荷、地址、端口、路径或文件名。"]
    if degraded:
        limitations.append("存在未成功分析的样本，结论不能覆盖全部提交范围。")
    if not evidence:
        limitations.append("当前规则未命中不能证明流量完全安全，必要时应扩大规则或补充上下文。")

    return AgentPcapImport(
        source_ref=source_ref,
        degraded=degraded,
        final_status=final_status,
        result_text=result_text,
        plan=(
            AgentPlanStep(step_id="step_01", tool_id="explain_pcap_capture", status="succeeded", summary="在本机隔离环境解析 PCAP"),
            AgentPlanStep(step_id="step_02", tool_id="explain_pcap_capture", status="succeeded", summary="定位并验证异常 Packet 证据", depends_on=("step_01",)),
            AgentPlanStep(step_id="step_03", tool_id=None, status="succeeded", summary="形成攻击候选与结论边界", depends_on=("step_02",)),
        ),
        observations=(
            AgentObservation(
                observation_id=f"observation_{result.detection_id.removeprefix('detection_')}",
                kind="pcap_detection_import",
                status="degraded" if degraded else "succeeded",
                summary=(f"已分析 {summary.analyzed_count} 个样本；成功 {summary.succeeded_count} 个，失败 {summary.failed_count} 个，异常证据 {len(evidence)} 条。"),
                observed_at=result.created_at,
                tool_id="explain_pcap_capture",
                evidence_refs=evidence_refs,
                retryable=degraded,
                public_error_code="partial_analysis" if degraded else None,
            ),
        ),
        evidence=evidence,
        hypotheses=_hypotheses(evidence),
        timeline=tuple(
            AgentTimelineEvent(
                timeline_id=f"timeline_{item.evidence_id}",
                occurred_at=item.observed_at,
                source_type=item.source_type,
                authenticity=item.authenticity,
                summary=item.summary,
                evidence_refs=(item.evidence_id,),
            )
            for item in evidence
        ),
        limitations=tuple(limitations),
    )


def _evidence(item, observed_at: str, source_ref: str) -> AgentEvidence:
    attack = _ATTACK_LABELS[str(item.attack_candidate)]
    packet_range = str(item.start_packet) if item.start_packet == item.end_packet else f"{item.start_packet}-{item.end_packet}"
    confidence = round(item.confidence * 100)
    return AgentEvidence(
        evidence_id=item.evidence_id,
        authenticity="real",
        source_type="pcap_detection",
        source_ref=source_ref,
        tool_id="explain_pcap_capture",
        summary=f"Packet {packet_range} 检出 {attack}候选，置信度 {confidence}%。",
        observed_at=observed_at,
        uncertainty="检测候选需要结合业务上下文复核，不能单独证明攻击成功。",
        metadata={
            "granularity": str(item.granularity),
            "verified_packet_count": item.verified_packet_count,
            "start_packet": item.start_packet,
            "end_packet": item.end_packet,
            "start_offset_ms": item.start_offset_ms,
            "end_offset_ms": item.end_offset_ms,
            "attack_candidate": str(item.attack_candidate),
            "detector": str(item.detector),
            "confidence": item.confidence,
            "supporting_signals": [str(value) for value in item.supporting_signals],
            "purpose_candidates": [str(value) for value in item.purpose_candidates],
        },
    )


def _hypotheses(evidence: tuple[AgentEvidence, ...]) -> tuple[AgentHypothesis, ...]:
    if not evidence:
        return (AgentHypothesis(hypothesis_id="hyp_01", title="存在未被当前规则覆盖的异常行为", status="inconclusive", confidence=0.35, limitations=("当前没有可定位的直接 Packet 证据。",)),)
    refs = tuple(item.evidence_id for item in evidence)
    confidence = max(float(item.metadata["confidence"]) for item in evidence)
    return (AgentHypothesis(hypothesis_id="hyp_01", title="存在需要复核的攻击流量候选", status="supported", confidence=confidence, supporting_evidence_refs=refs, limitations=("检测候选不等于攻击已经成功。",)),)
