from __future__ import annotations

import pytest

from app.lab.models import LabToolId
from app.schemas import Decision
from app.superagent.models import (
    SuperAgentExecutionReference,
    SuperAgentFinalStatus,
)
from app.superagent.policy import final_status_for, response_tools_for


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        (Decision.ALLOW, ()),
        (
            Decision.REVIEW,
            (LabToolId.SECURITY_CASE, LabToolId.EVIDENCE_BUNDLE),
        ),
        (
            Decision.SANITIZE_RECHECK,
            (LabToolId.SECURITY_CASE, LabToolId.EVIDENCE_BUNDLE),
        ),
        (
            Decision.BLOCK,
            (
                LabToolId.GATEWAY_ENFORCEMENT,
                LabToolId.SECURITY_CASE,
                LabToolId.EVIDENCE_BUNDLE,
            ),
        ),
    ],
)
def test_response_tools_are_bounded(
    decision: Decision, expected: tuple[LabToolId, ...]
) -> None:
    assert response_tools_for(decision) == expected


def _execution(
    tool_id: LabToolId, *, status: str = "succeeded"
) -> SuperAgentExecutionReference:
    return SuperAgentExecutionReference(
        execution_id=f"exec_{tool_id.value[:8]:0<32}",
        tool_id=tool_id,
        status=status,
        source_action=Decision.BLOCK,
        effective_action=Decision.BLOCK,
    )


def test_final_status_requires_all_selected_tools_to_succeed() -> None:
    selected = response_tools_for(Decision.BLOCK)
    succeeded = tuple(_execution(tool_id) for tool_id in selected)

    assert final_status_for(Decision.BLOCK, selected, succeeded) is (
        SuperAgentFinalStatus.CONTAINED
    )
    assert final_status_for(
        Decision.BLOCK,
        selected,
        succeeded[:-1] + (_execution(selected[-1], status="failed"),),
    ) is SuperAgentFinalStatus.DEGRADED
    assert final_status_for(
        Decision.BLOCK, selected, succeeded[:-1]
    ) is SuperAgentFinalStatus.DEGRADED


def test_final_status_matches_safe_and_review_policy() -> None:
    assert final_status_for(Decision.ALLOW, (), ()) is (
        SuperAgentFinalStatus.CLOSED_SAFE
    )
    selected = response_tools_for(Decision.REVIEW)
    executions = tuple(
        SuperAgentExecutionReference(
            execution_id=f"exec_{tool.value[:8]:0<32}",
            tool_id=tool,
            status="succeeded",
            source_action=Decision.REVIEW,
            effective_action=Decision.REVIEW,
        )
        for tool in selected
    )
    assert final_status_for(Decision.REVIEW, selected, executions) is (
        SuperAgentFinalStatus.REVIEW_REQUIRED
    )


def test_final_status_rejects_duplicate_or_unselected_tools() -> None:
    selected = response_tools_for(Decision.BLOCK)
    duplicate = (_execution(selected[0]), _execution(selected[0]))

    with pytest.raises(ValueError, match="exactly once"):
        final_status_for(Decision.BLOCK, selected, duplicate)


def test_final_status_rejects_execution_actions_from_another_mission() -> None:
    selected = response_tools_for(Decision.BLOCK)
    mismatched = tuple(
        SuperAgentExecutionReference(
            execution_id=f"exec_{index:032x}",
            tool_id=tool_id,
            status="succeeded",
            source_action=Decision.ALLOW,
            effective_action=Decision.ALLOW,
        )
        for index, tool_id in enumerate(selected, start=1)
    )

    with pytest.raises(ValueError, match="mission decision"):
        final_status_for(Decision.BLOCK, selected, mismatched)
