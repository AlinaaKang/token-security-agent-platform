from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas import NonEmptyText
from app.security_agent.adapters import adapt_tool_output
from app.security_agent.models import AgentEvidence, AgentObservation


EXPECTED_SECURITY_TOOL_IDS = frozenset(
    {
        "analyze_prompt",
        "counterfactual_recheck",
        "inspect_pcap_dataset",
        "detect_pcap_batch",
        "explain_pcap_capture",
        "retrieve_security_knowledge",
        "explain_attack",
        "explain_protocol",
        "generate_case_report",
        "preview_response_action",
        "execute_internal_action",
        "query_simulated_telemetry",
        "map_attack_framework",
        "search_similar_cases",
        "simulate_response_options",
        "verify_response_effect",
        "record_analyst_feedback",
    }
)


class SecurityToolUnavailable(RuntimeError):
    pass


class SecurityToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: NonEmptyText
    title: NonEmptyText
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    permission_level: Literal["read", "authorized_read", "internal_action"]
    timeout_seconds: int = Field(ge=1, le=120)
    retry_count: int = Field(ge=0, le=2)
    concurrency_cost: int = Field(ge=1, le=3)
    privacy_level: Literal["public", "transient_private"]
    auto_executable: bool


class SecurityToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    objective_id: NonEmptyText | None = None
    observation: AgentObservation
    evidence: tuple[AgentEvidence, ...] = Field(default=(), max_length=200)


class SecurityToolRegistry:
    def __init__(
        self,
        specs: tuple[SecurityToolSpec, ...],
        handlers: Mapping[str, Callable[[dict[str, object]], Any]],
    ) -> None:
        self._specs = {spec.tool_id: spec for spec in specs}
        self._handlers = dict(handlers)

    def ids(self) -> tuple[str, ...]:
        return tuple(self._specs)

    def spec(self, tool_id: str) -> SecurityToolSpec:
        try:
            return self._specs[tool_id]
        except KeyError:
            raise KeyError(f"unknown security tool: {tool_id}") from None

    def execute(self, tool_id: str, arguments: dict[str, object]) -> SecurityToolResult:
        spec = self.spec(tool_id)
        _validate_arguments(spec, arguments)
        handler = self._handlers.get(tool_id)
        if handler is None:
            raise SecurityToolUnavailable(f"security tool unavailable: {tool_id}")
        adapted = adapt_tool_output(tool_id, handler(dict(arguments)))
        return SecurityToolResult.model_validate(adapted)

    def on_task_switch(self, previous_task_id: str, next_task_id: str) -> None:
        del previous_task_id, next_task_id
        # Task selection changes subscriptions only; cancellation is always explicit.


def build_registry(
    dependencies: Mapping[str, Callable[[dict[str, object]], Any]] | Any,
) -> SecurityToolRegistry:
    handlers = dependencies if isinstance(dependencies, Mapping) else {
        tool_id: getattr(dependencies, tool_id)
        for tool_id in EXPECTED_SECURITY_TOOL_IDS
        if callable(getattr(dependencies, tool_id, None))
    }
    return SecurityToolRegistry(_specs(), handlers)


def _schema(*required: str, optional: tuple[str, ...] = ()) -> dict[str, Any]:
    properties = {key: {"type": "string"} for key in required + optional}
    if "start_index" in properties:
        properties["start_index"] = {"type": "integer", "minimum": 0}
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def _specs() -> tuple[SecurityToolSpec, ...]:
    output = {"type": "object", "additionalProperties": True}
    definitions = (
        ("analyze_prompt", "Prompt 安全检测", _schema("input_ref"), "authorized_read", 120, 1, 2, "transient_private", False),
        ("counterfactual_recheck", "反事实复核", _schema("input_ref"), "authorized_read", 120, 1, 2, "transient_private", False),
        ("inspect_pcap_dataset", "PCAP 数据集画像", _schema("authorization_ref"), "authorized_read", 60, 1, 2, "transient_private", False),
        ("detect_pcap_batch", "PCAP 批量检测", _schema("authorization_ref", optional=("start_index",)), "authorized_read", 120, 1, 3, "transient_private", False),
        ("explain_pcap_capture", "PCAP 证据解释", _schema("evidence_ref"), "authorized_read", 30, 0, 1, "public", True),
        ("retrieve_security_knowledge", "安全知识检索", _schema("evidence_ref"), "read", 20, 1, 1, "public", True),
        ("explain_attack", "攻击科普", _schema("knowledge_ref"), "read", 20, 0, 1, "public", True),
        ("explain_protocol", "协议与过滤器解释", _schema("evidence_ref"), "read", 20, 0, 1, "public", True),
        ("generate_case_report", "案件报告生成", _schema("task_ref"), "read", 30, 0, 1, "public", True),
        ("preview_response_action", "处置预览", _schema("task_ref"), "read", 20, 0, 1, "public", True),
        ("execute_internal_action", "内部处置执行", _schema("authorization_ref", "action_ref"), "internal_action", 30, 0, 2, "transient_private", False),
        ("query_simulated_telemetry", "仿真遥测查询", _schema("case_id"), "authorized_read", 10, 0, 1, "public", False),
        ("map_attack_framework", "攻击框架映射", _schema("evidence_ref"), "read", 20, 0, 1, "public", True),
        ("search_similar_cases", "相似案件检索", _schema("evidence_ref"), "read", 20, 0, 1, "public", True),
        ("simulate_response_options", "处置方案推演", _schema("task_ref"), "read", 20, 0, 1, "public", True),
        ("verify_response_effect", "处置效果验证", _schema("action_ref"), "read", 30, 1, 1, "public", True),
        ("record_analyst_feedback", "分析员反馈", _schema("authorization_ref", "task_ref"), "internal_action", 10, 0, 1, "public", False),
    )
    return tuple(
        SecurityToolSpec(
            tool_id=tool_id,
            title=title,
            input_schema=input_schema,
            output_schema=output,
            permission_level=permission,
            timeout_seconds=timeout,
            retry_count=retries,
            concurrency_cost=cost,
            privacy_level=privacy,
            auto_executable=automatic,
        )
        for tool_id, title, input_schema, permission, timeout, retries, cost, privacy, automatic in definitions
    )


def _validate_arguments(spec: SecurityToolSpec, arguments: dict[str, object]) -> None:
    schema = spec.input_schema
    required = set(schema.get("required", ()))
    properties = set(schema.get("properties", {}))
    missing = required - set(arguments)
    unknown = set(arguments) - properties
    if missing:
        raise ValueError(f"missing tool input: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"unknown tool input: {', '.join(sorted(unknown))}")
    for key in required:
        value = arguments[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a non-empty reference")
    if "start_index" in arguments:
        value = arguments["start_index"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("start_index must be a non-negative integer")

