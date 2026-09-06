from __future__ import annotations

import pytest

from app.security_agent.tools import (
    EXPECTED_SECURITY_TOOL_IDS,
    SecurityToolUnavailable,
    build_registry,
)


def test_registry_exposes_only_declared_tools() -> None:
    registry = build_registry({})

    assert set(registry.ids()) == EXPECTED_SECURITY_TOOL_IDS


def test_every_tool_declares_bounded_execution_contract() -> None:
    registry = build_registry({})

    for tool_id in registry.ids():
        spec = registry.spec(tool_id)
        assert spec.input_schema
        assert spec.output_schema
        assert spec.permission_level in {"read", "authorized_read", "internal_action"}
        assert 1 <= spec.timeout_seconds <= 120
        assert 0 <= spec.retry_count <= 2
        assert 1 <= spec.concurrency_cost <= 3
        assert spec.privacy_level in {"public", "transient_private"}
        assert isinstance(spec.auto_executable, bool)


def test_unknown_tool_is_rejected() -> None:
    registry = build_registry({})

    with pytest.raises(KeyError):
        registry.spec("shell_exec")


def test_unconfigured_real_tool_reports_unavailable() -> None:
    registry = build_registry({})

    with pytest.raises(SecurityToolUnavailable, match="analyze_prompt"):
        registry.execute("analyze_prompt", {"input_ref": "transient:prompt"})


def test_registry_validates_input_schema_before_calling_handler() -> None:
    calls: list[dict[str, object]] = []
    registry = build_registry({"analyze_prompt": lambda value: calls.append(value)})

    with pytest.raises(ValueError, match="input_ref"):
        registry.execute("analyze_prompt", {"unexpected": "value"})
    assert calls == []

