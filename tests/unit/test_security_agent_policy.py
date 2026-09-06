from __future__ import annotations

import pytest

from app.security_agent.models import AgentCapabilities, AgentPlanStep
from app.security_agent.policy import AgentPlanRejected, validate_plan


def capabilities() -> AgentCapabilities:
    return AgentCapabilities(
        planner_mode="deterministic_fallback",
        tool_ids=(
            "inspect_pcap_dataset",
            "detect_pcap_batch",
            "explain_pcap_capture",
            "inspect_encrypted_flow_behavior",
            "preview_response_action",
            "execute_internal_action",
        ),
        connector_states={"pcap_docker": "available"},
    )


def step(
    number: int,
    tool_id: str,
    *,
    depends_on: tuple[str, ...] = (),
    requires_authorization: bool = False,
) -> AgentPlanStep:
    return AgentPlanStep(
        step_id=f"step_{number:02d}",
        tool_id=tool_id,
        status="waiting",
        requires_authorization=requires_authorization,
        summary=f"运行 {tool_id}",
        depends_on=depends_on,
    )


def test_policy_rejects_model_proposed_unknown_tool() -> None:
    with pytest.raises(AgentPlanRejected, match="unknown tool"):
        validate_plan((step(1, "shell_exec"),), capabilities(), frozenset())


def test_policy_rejects_more_than_twelve_steps() -> None:
    plan = tuple(step(index, "detect_pcap_batch") for index in range(1, 13)) + (
        AgentPlanStep(
            step_id="step_13",
            tool_id="detect_pcap_batch",
            status="waiting",
            summary="越界步骤",
        ),
    )

    with pytest.raises((AgentPlanRejected, ValueError)):
        validate_plan(plan, capabilities(), frozenset())


def test_policy_rejects_dependency_cycle() -> None:
    plan = (
        step(1, "inspect_pcap_dataset", depends_on=("step_02",)),
        step(2, "detect_pcap_batch", depends_on=("step_01",)),
    )

    with pytest.raises(AgentPlanRejected, match="cycle"):
        validate_plan(plan, capabilities(), frozenset())


def test_policy_rejects_missing_authorization_scope() -> None:
    plan = (step(1, "detect_pcap_batch", requires_authorization=True),)

    with pytest.raises(AgentPlanRejected, match="authorization"):
        validate_plan(plan, capabilities(), frozenset())


def test_policy_accepts_authorized_bounded_plan() -> None:
    plan = (
        step(1, "inspect_pcap_dataset", requires_authorization=True),
        step(2, "detect_pcap_batch", depends_on=("step_01",), requires_authorization=True),
    )

    assert validate_plan(plan, capabilities(), frozenset({"pcap:read"})) == plan


def test_policy_rejects_automatic_external_action() -> None:
    plan = (step(1, "execute_internal_action"),)

    with pytest.raises(AgentPlanRejected, match="action authorization"):
        validate_plan(plan, capabilities(), frozenset())


def test_policy_rejects_simulation_tool_on_real_task() -> None:
    caps = capabilities().model_copy(
        update={"tool_ids": capabilities().tool_ids + ("query_simulated_telemetry",)}
    )

    with pytest.raises(AgentPlanRejected, match="demo scope"):
        validate_plan(
            (step(1, "query_simulated_telemetry"),),
            caps,
            frozenset({"pcap:read"}),
        )

