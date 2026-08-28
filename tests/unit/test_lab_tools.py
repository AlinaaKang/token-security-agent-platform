from __future__ import annotations

import builtins
import socket
import subprocess

import pytest

from app.knowledge.models import KnowledgeEvidence
from app.lab.models import LabToolId
from app.lab.tools import build_response_plan, execute_dry_run


def _evidence() -> KnowledgeEvidence:
    return KnowledgeEvidence.model_validate(
        {
            "knowledge_id": "owasp-llm01-prompt-injection",
            "title_zh": "提示词注入控制",
            "risk_domain": "prompt_injection",
            "summary": "使用分层控制限制提示词注入风险。",
            "recommendations": ["保留安全判定并记录结构化证据。"],
            "source": {
                "publisher": "owasp",
                "title": "OWASP GenAI Security Project",
                "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                "version": "2025",
                "verified_at": "2026-08-26T00:00:00Z",
                "usage_note": "official summary",
            },
            "retrieval_score": 4.0,
            "matched_tags": ["jailbreak"],
        }
    )


@pytest.mark.parametrize(
    "decision, expected_gateway_action",
    [
        ("allow", "allow"),
        ("review", "review"),
        ("block", "block"),
    ],
)
def test_response_plan_has_only_the_three_fixed_tools(
    decision: str, expected_gateway_action: str
) -> None:
    plans = build_response_plan(
        decision=decision,
        fusion_reason="cpd_candidate",
        mode="gateway",
        evidence=(_evidence(),),
    )

    assert [plan.tool_id for plan in plans] == [
        LabToolId.GATEWAY_ENFORCEMENT,
        LabToolId.SECURITY_CASE,
        LabToolId.EVIDENCE_BUNDLE,
    ]
    assert plans[0].effective_action == expected_gateway_action
    assert all(plan.status == "planned" for plan in plans)
    assert all(
        plan.knowledge_ids == ("owasp-llm01-prompt-injection",)
        for plan in plans
    )


def test_dry_run_performs_no_network_file_or_subprocess_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plans = build_response_plan(
        decision="review",
        fusion_reason="semantic_controversial",
        mode="analysis",
        evidence=(_evidence(),),
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external side effect attempted")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)

    results = [execute_dry_run(plan, inject_failure=False) for plan in plans]

    assert [result.status for result in results] == [
        "succeeded",
        "succeeded",
        "succeeded",
    ]
    assert all(result.error_code is None for result in results)
    assert results[2].evidence_sha256 is not None
    assert results[2].evidence_sha256.startswith("sha256:")


def test_injected_failure_uses_a_fixed_error_and_never_downgrades_block() -> None:
    plan = build_response_plan(
        decision="block",
        fusion_reason="semantic_unsafe",
        mode="gateway",
        evidence=(_evidence(),),
    )[0]

    result = execute_dry_run(plan, inject_failure=True)

    assert result.status == "failed"
    assert result.error_code == "simulated_tool_failure"
    assert result.effective_action == "block"
    assert result.evidence_sha256 is None
    assert "预览" in result.artifact_summary


def test_dry_run_result_contains_no_execution_parameters() -> None:
    plan = build_response_plan(
        decision="allow",
        fusion_reason="all_clear",
        mode="analysis",
        evidence=(),
    )[0]

    payload = execute_dry_run(plan, inject_failure=False).model_dump(mode="json")

    assert set(payload) == {
        "tool_id",
        "status",
        "error_code",
        "latency_ms",
        "effective_action",
        "artifact_summary",
        "evidence_sha256",
    }
    assert not {"url", "path", "command", "credential"}.intersection(payload)


def test_dry_run_is_explicitly_a_preview_of_the_internal_tools() -> None:
    plan = build_response_plan(
        decision="review",
        fusion_reason="semantic_controversial",
        mode="analysis",
        evidence=(),
    )[0]

    result = execute_dry_run(plan, inject_failure=False)

    assert plan.tool_id is LabToolId.GATEWAY_ENFORCEMENT
    assert "预览" in plan.artifact_summary
    assert "平台内部执行" not in plan.artifact_summary
    assert "预览" in result.artifact_summary
