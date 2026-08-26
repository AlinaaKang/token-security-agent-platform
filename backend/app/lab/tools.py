from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Sequence

from app.knowledge.models import KnowledgeEvidence
from app.lab.models import (
    LabToolId,
    LabToolPlan,
    ToolDryRunResult,
    safer_action,
)
from app.schemas import Decision


_TOOL_TITLES = {
    LabToolId.GATEWAY_PREVIEW: "网关策略预览",
    LabToolId.SOC_CASE_PREVIEW: "安全工单预览",
    LabToolId.EVIDENCE_EXPORT_PREVIEW: "证据清单预览",
}


def build_response_plan(
    *,
    decision: Decision | str,
    fusion_reason: str,
    mode: str,
    evidence: Sequence[KnowledgeEvidence],
) -> tuple[LabToolPlan, ...]:
    action = Decision(decision)
    knowledge_ids = tuple(item.knowledge_id for item in evidence)
    context = f"基础动作 {action.value}；模式 {mode}；融合依据 {fusion_reason}。"
    summaries = {
        LabToolId.GATEWAY_PREVIEW: f"预览网关执行 {action.value}；{context}",
        LabToolId.SOC_CASE_PREVIEW: f"预览脱敏安全工单；{context}",
        LabToolId.EVIDENCE_EXPORT_PREVIEW: f"预览结构化证据清单；{context}",
    }
    return tuple(
        LabToolPlan(
            tool_id=tool_id,
            title=_TOOL_TITLES[tool_id],
            effective_action=action,
            artifact_summary=summaries[tool_id],
            knowledge_ids=knowledge_ids,
        )
        for tool_id in LabToolId
    )


def execute_dry_run(
    plan: LabToolPlan, *, inject_failure: bool
) -> ToolDryRunResult:
    started = time.perf_counter()
    if inject_failure:
        return ToolDryRunResult(
            tool_id=plan.tool_id,
            status="failed",
            error_code="simulated_tool_failure",
            latency_ms=(time.perf_counter() - started) * 1000,
            effective_action=safer_action(plan.effective_action, Decision.REVIEW),
            artifact_summary="模拟工具失败；保留基础动作或升级人工复核。",
        )

    evidence_sha256 = None
    if plan.tool_id is LabToolId.EVIDENCE_EXPORT_PREVIEW:
        serialized = json.dumps(
            {
                "tool_id": plan.tool_id.value,
                "effective_action": plan.effective_action.value,
                "artifact_summary": plan.artifact_summary,
                "knowledge_ids": list(plan.knowledge_ids),
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        evidence_sha256 = "sha256:" + hashlib.sha256(serialized).hexdigest()
    return ToolDryRunResult(
        tool_id=plan.tool_id,
        status="succeeded",
        latency_ms=(time.perf_counter() - started) * 1000,
        effective_action=plan.effective_action,
        artifact_summary=plan.artifact_summary,
        evidence_sha256=evidence_sha256,
    )
