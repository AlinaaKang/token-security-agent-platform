from __future__ import annotations

from collections.abc import Iterable

from app.security_agent.models import AgentCapabilities, AgentPlanStep


class AgentPlanRejected(ValueError):
    pass


_AUTHORIZATION_BY_TOOL = {
    "analyze_prompt": "prompt:analyze",
    "counterfactual_recheck": "prompt:analyze",
    "inspect_pcap_dataset": "pcap:read",
    "detect_pcap_batch": "pcap:read",
    "explain_pcap_capture": "pcap:read",
    "inspect_encrypted_flow_behavior": "pcap:read",
    "execute_internal_action": "response:execute",
    "record_analyst_feedback": "feedback:write",
    "query_simulated_telemetry": "demo:use",
}


def validate_plan(
    plan: Iterable[AgentPlanStep],
    capabilities: AgentCapabilities,
    authorization_scope: frozenset[str] | set[str],
) -> tuple[AgentPlanStep, ...]:
    steps = tuple(plan)
    if len(steps) > capabilities.max_plan_steps:
        raise AgentPlanRejected("plan exceeds maximum step count")
    identifiers = [step.step_id for step in steps]
    if len(identifiers) != len(set(identifiers)):
        raise AgentPlanRejected("duplicate plan step id")
    known_tools = set(capabilities.tool_ids)
    scopes = frozenset(authorization_scope)
    for step in steps:
        if step.tool_id is None:
            continue
        if step.tool_id not in known_tools:
            raise AgentPlanRejected(f"unknown tool: {step.tool_id}")
        missing_dependencies = set(step.depends_on) - set(identifiers)
        if missing_dependencies:
            raise AgentPlanRejected("plan references an unknown dependency")
        required_scope = _AUTHORIZATION_BY_TOOL.get(step.tool_id)
        if step.tool_id == "execute_internal_action" and required_scope not in scopes:
            raise AgentPlanRejected("response action authorization is required")
        if step.tool_id == "query_simulated_telemetry" and required_scope not in scopes:
            raise AgentPlanRejected("simulation requires explicit demo scope")
        if step.requires_authorization and required_scope not in scopes:
            raise AgentPlanRejected("required authorization scope is missing")
    _reject_dependency_cycles(steps)
    return steps


def _reject_dependency_cycles(steps: tuple[AgentPlanStep, ...]) -> None:
    dependencies = {step.step_id: set(step.depends_on) for step in steps}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(step_id: str) -> None:
        if step_id in visiting:
            raise AgentPlanRejected("plan dependency cycle detected")
        if step_id in visited:
            return
        visiting.add(step_id)
        for dependency in dependencies[step_id]:
            visit(dependency)
        visiting.remove(step_id)
        visited.add(step_id)

    for identifier in dependencies:
        visit(identifier)

