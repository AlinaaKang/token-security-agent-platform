from __future__ import annotations

from collections.abc import Sequence

from app.knowledge.models import KnowledgeEvidence
from app.lab.models import (
    CounterfactualResult,
    LabCaseReport,
    ToolDryRunResult,
    assert_public_payload,
)
from app.schemas import Decision


def build_case_report(
    *,
    decision: Decision | str,
    evidence: Sequence[KnowledgeEvidence],
    counterfactual: CounterfactualResult,
    tool_results: Sequence[ToolDryRunResult],
    requested_evidence_ids: Sequence[str],
) -> LabCaseReport:
    action = Decision(decision)
    valid_ids = tuple(item.knowledge_id for item in evidence)
    requested = tuple(requested_evidence_ids)
    citations_valid = set(requested).issubset(set(valid_ids))
    selected_ids = requested if citations_valid else valid_ids
    if not requested and valid_ids:
        selected_ids = valid_ids

    limitations = [
        "反事实结果仅为敏感性证据，不构成严格因果证明。",
        "所有处置工具均为模拟执行，不代表外部系统已变更。",
    ]
    if not evidence:
        limitations.append("知识证据不可用，报告仅汇总基础检测结果。")

    handling = {
        Decision.ALLOW: ("保留放行预览，并持续观察后续安全事件。",),
        Decision.REVIEW: ("保留人工复核动作，核验结构化证据后再处置。",),
        Decision.SANITIZE_RECHECK: ("保留净化重检动作，不直接放行原请求。",),
        Decision.BLOCK: ("保留拦截动作，并生成脱敏调查记录。",),
    }[action]
    report = LabCaseReport(
        report_status="deterministic" if citations_valid else "fallback",
        summary=(
            f"基础检测动作为 {action.value}；反事实敏感性结论为 "
            f"{counterfactual.interpretation}。"
        ),
        evidence_ids=selected_ids,
        handling_steps=handling,
        limitations=tuple(limitations),
        tool_statuses={result.tool_id: result.status for result in tool_results},
    )
    assert_public_payload(report)
    return report
