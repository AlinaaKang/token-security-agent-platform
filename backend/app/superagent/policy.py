from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from app.lab.models import LabToolId
from app.schemas import Decision
from app.superagent.models import (
    SuperAgentExecutionReference,
    SuperAgentFinalStatus,
)


_REVIEW_TOOLS = (
    LabToolId.SECURITY_CASE,
    LabToolId.EVIDENCE_BUNDLE,
)
_BLOCK_TOOLS = (
    LabToolId.GATEWAY_ENFORCEMENT,
    LabToolId.SECURITY_CASE,
    LabToolId.EVIDENCE_BUNDLE,
)


def response_tools_for(decision: Decision | str) -> tuple[LabToolId, ...]:
    action = Decision(decision)
    if action is Decision.ALLOW:
        return ()
    if action in {Decision.REVIEW, Decision.SANITIZE_RECHECK}:
        return _REVIEW_TOOLS
    return _BLOCK_TOOLS


def final_status_for(
    decision: Decision | str,
    selected_tools: Sequence[LabToolId],
    executions: Sequence[SuperAgentExecutionReference],
) -> SuperAgentFinalStatus:
    action = Decision(decision)
    selected = tuple(LabToolId(tool) for tool in selected_tools)
    expected = response_tools_for(action)
    if selected != expected:
        raise ValueError("selected tools must match the bounded response policy")

    executed_tools = tuple(item.tool_id for item in executions)
    counts = Counter(executed_tools)
    if any(count > 1 for count in counts.values()):
        raise ValueError("each selected tool must execute exactly once")
    if any(tool not in selected for tool in executed_tools):
        raise ValueError("execution contains an unselected tool")
    if any(
        item.source_action is not action or item.effective_action is not action
        for item in executions
    ):
        raise ValueError("execution action must match the mission decision")
    if len(executions) != len(selected):
        return SuperAgentFinalStatus.DEGRADED
    if executed_tools != selected:
        return SuperAgentFinalStatus.DEGRADED
    if any(item.status != "succeeded" for item in executions):
        return SuperAgentFinalStatus.DEGRADED
    if action is Decision.ALLOW:
        return SuperAgentFinalStatus.CLOSED_SAFE
    if action in {Decision.REVIEW, Decision.SANITIZE_RECHECK}:
        return SuperAgentFinalStatus.REVIEW_REQUIRED
    return SuperAgentFinalStatus.CONTAINED
