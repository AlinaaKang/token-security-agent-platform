from __future__ import annotations

from collections.abc import Iterable

from app.security_agent.models import AgentEvidence, AgentHypothesis


class AgentReportError(ValueError):
    pass


def render_case_report(
    *,
    title: str,
    objective: str,
    evidence: Iterable[AgentEvidence],
    hypotheses: Iterable[AgentHypothesis],
    limitations: Iterable[str],
    final_status: str,
) -> str:
    evidence_items = tuple(evidence)
    hypothesis_items = tuple(hypotheses)
    evidence_ids = {item.evidence_id for item in evidence_items}
    for hypothesis in hypothesis_items:
        referenced = set(hypothesis.supporting_evidence_refs) | set(
            hypothesis.opposing_evidence_refs
        )
        if not referenced.issubset(evidence_ids):
            raise AgentReportError("hypothesis references unknown evidence")

    lines = [
        f"# {title}",
        "",
        f"- 调查目标：{objective}",
        f"- 最终状态：{final_status}",
        "",
        "## 调查结论",
        "",
        _conclusion(evidence_items, final_status),
    ]
    for authenticity, heading in (
        ("real", "真实证据"),
        ("simulated", "仿真证据"),
        ("derived", "派生证据"),
    ):
        lines.extend(["", f"## {heading}", ""])
        matching = [item for item in evidence_items if item.authenticity == authenticity]
        if matching:
            lines.extend(
                f"- [{item.evidence_id}] {item.summary} 限制：{item.uncertainty}"
                for item in matching
            )
        else:
            lines.append("- 当前案件无此类证据。")

    lines.extend(["", "## 候选假设与完整审查链", ""])
    if not hypothesis_items:
        lines.append("- 当前没有足够证据建立候选假设。")
    for hypothesis in hypothesis_items:
        support = ", ".join(f"[{item}]" for item in hypothesis.supporting_evidence_refs) or "无"
        oppose = ", ".join(f"[{item}]" for item in hypothesis.opposing_evidence_refs) or "无"
        lines.extend(
            [
                f"### {hypothesis.title}",
                f"- 状态与置信度：{hypothesis.status} / {hypothesis.confidence:.0%}",
                f"- 支持证据：{support}",
                f"- 反对证据：{oppose}",
            ]
        )
        for change in hypothesis.confidence_changes:
            refs = ", ".join(f"[{item}]" for item in change.evidence_refs)
            lines.append(
                f"- 置信度变化：{change.before:.0%} -> {change.after:.0%}；{change.reason} {refs}"
            )

    lines.extend(["", "## 攻击目的候选", ""])
    lines.append("- 目的仅依据已引用证据推断，不等同于攻击结果确认。")
    lines.extend(["", "## 不能证明", ""])
    lines.append("- 异常候选不能单独证明攻击已经成功或数据已经泄露。")
    lines.extend(["", "## 未覆盖与失败", ""])
    limitations_tuple = tuple(limitations)
    lines.extend(f"- {item}" for item in limitations_tuple or ("当前没有额外限制记录。",))
    lines.extend(["", "## 建议", ""])
    lines.append("- 复核直接证据、失败项和未覆盖数据源后，再决定是否扩大处置范围。")
    lines.extend(["", "## 处置与验证", ""])
    lines.append(
        "- 只有独立验证观察为已生效时，案件才可标记为已闭环；否则保持待复核或结论不充分。"
    )
    return "\n".join(lines) + "\n"


def _conclusion(evidence: tuple[AgentEvidence, ...], final_status: str) -> str:
    real_count = sum(item.authenticity == "real" for item in evidence)
    simulated_count = sum(item.authenticity == "simulated" for item in evidence)
    return (
        f"当前状态为 {final_status}，包含 {real_count} 条真实证据和 "
        f"{simulated_count} 条明确标注的仿真证据。"
    )

