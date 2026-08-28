from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.lab.models import (
    LabPublicSignal,
    LabRunRequest,
    LabToolId,
    ToolDryRunRequest,
    assert_public_payload,
    safer_action,
)
from app.schemas import TokenSignal


def test_lab_run_request_requires_exactly_one_input_source() -> None:
    custom = LabRunRequest(
        scenario_kind="custom",
        custom_input="Explain why input validation matters.",
        mode="analysis",
    )
    frozen = LabRunRequest(
        scenario_kind="frozen",
        sample_id="sample_01",
        mode="gateway",
    )

    assert custom.custom_input == "Explain why input validation matters."
    assert custom.sample_id is None
    assert frozen.custom_input is None
    assert frozen.sample_id == "sample_01"

    with pytest.raises(ValidationError):
        LabRunRequest(
            scenario_kind="custom",
            custom_input="safe text",
            sample_id="sample_01",
        )
    with pytest.raises(ValidationError):
        LabRunRequest(scenario_kind="frozen")
    with pytest.raises(ValidationError):
        LabRunRequest(scenario_kind="frozen", custom_input="safe text")


def test_tool_request_has_no_free_form_execution_parameters() -> None:
    assert ToolDryRunRequest(inject_failure=True).model_dump() == {
        "inject_failure": True
    }
    assert {tool.value for tool in LabToolId} == {
        "gateway_enforcement",
        "security_case",
        "evidence_bundle",
    }

    with pytest.raises(ValidationError):
        ToolDryRunRequest(
            inject_failure=False,
            url="https://example.invalid",
            command="run",
        )


def test_public_signal_removes_token_identity_and_text() -> None:
    signal = TokenSignal(
        index=3,
        token_id=4201,
        token_text="PRIVATE_TOKEN",
        entropy=1.25,
        nll=2.5,
        cpd_entropy=3.75,
        cpd_nll=0.0,
        risk=0.6,
    )

    public = LabPublicSignal.from_token_signal(signal)

    assert public.model_dump(mode="json") == {
        "index": 3,
        "entropy": 1.25,
        "nll": 2.5,
        "cpd_entropy": 3.75,
        "cpd_nll": 0.0,
        "risk": 0.6,
    }


@pytest.mark.parametrize(
    "payload, expected_key",
    [
        ({"prompt": "secret"}, "prompt"),
        ({"outer": [{"suffix": "secret"}]}, "suffix"),
        ({"outer": ({"token_text": "secret"},)}, "token_text"),
        ({"token_id": 91}, "token_id"),
        ({"query_text": "secret"}, "query_text"),
        ({"raw_output": "secret"}, "raw_output"),
        ({"guard_raw_output": "secret"}, "guard_raw_output"),
        ({"hidden_reasoning": "secret"}, "hidden_reasoning"),
    ],
)
def test_public_payload_rejects_forbidden_keys_at_any_depth(
    payload: object, expected_key: str
) -> None:
    with pytest.raises(
        ValueError, match=f"lab payload contains forbidden field: {expected_key}"
    ):
        assert_public_payload(payload)


def test_public_payload_accepts_redacted_structured_evidence() -> None:
    payload = {
        "run_id": "lab_123",
        "signals": [{"index": 0, "entropy": 1.2}],
        "report": {"evidence_ids": ["owasp-llm01-prompt-injection"]},
    }

    assert_public_payload(payload)


@pytest.mark.parametrize(
    "original, proposed, expected",
    [
        ("allow", "review", "review"),
        ("allow", "block", "block"),
        ("review", "allow", "review"),
        ("review", "block", "block"),
        ("block", "allow", "block"),
        ("block", "review", "block"),
        ("block", "block", "block"),
        ("sanitize_recheck", "allow", "sanitize_recheck"),
        ("sanitize_recheck", "block", "block"),
    ],
)
def test_safer_action_never_downgrades_the_original_action(
    original: str, proposed: str, expected: str
) -> None:
    assert safer_action(original, proposed) == expected
