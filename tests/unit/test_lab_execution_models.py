from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.lab.execution_models import (
    LabArtifact,
    LabExecuteRequest,
    LabSecurityCase,
    LabToolExecution,
)
from app.lab.models import LabToolId


_TIME = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
_KEY = UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff")


def _execution(**changes: object) -> LabToolExecution:
    values: dict[str, object] = {
        "execution_id": "execution-001",
        "run_id": "run-001",
        "tool_id": LabToolId.GATEWAY_ENFORCEMENT,
        "idempotency_key": _KEY,
        "status": "succeeded",
        "source_action": "block",
        "effective_action": "block",
        "receipt_id": "receipt-001",
        "artifact_id": "artifact-001",
        "error_code": None,
        "evidence_sha256": "sha256:" + "a" * 64,
        "latency_ms": 12.5,
        "created_at": _TIME,
    }
    values.update(changes)
    return LabToolExecution.model_validate(values)


def _security_case(**changes: object) -> LabSecurityCase:
    values: dict[str, object] = {
        "case_id": "case-001",
        "run_id": "run-001",
        "created_at": _TIME,
        "risk_score": 0.9,
        "semantic_severity": "unsafe",
        "semantic_categories": ["jailbreak"],
        "detector_status": "token_anomaly_candidate",
        "anomaly_char_start": 12,
        "fusion_reason": "semantic_unsafe",
        "effective_action": "block",
        "handling_status": "open",
        "knowledge_ids": ["owasp-llm01-prompt-injection"],
        "model_id": "semantic-guard-v1",
        "calibration_version": "2026-08",
        "knowledge_snapshot_version": "2026-08-28",
        "execution_id": "execution-001",
        "receipt_id": "receipt-001",
    }
    values.update(changes)
    return LabSecurityCase.model_validate(values)


def _artifact(**changes: object) -> LabArtifact:
    values: dict[str, object] = {
        "artifact_id": "artifact-001",
        "run_id": "run-001",
        "execution_id": "execution-001",
        "media_type": "application/json",
        "payload": b'{"decision":"block"}',
        "sha256": "sha256:" + "b" * 64,
        "created_at": _TIME,
    }
    values.update(changes)
    return LabArtifact.model_validate(values)


def test_execute_request_requires_an_explicit_confirmation_and_uuid_key() -> None:
    request = LabExecuteRequest(confirmed=True, idempotency_key=_KEY)

    assert request.confirmed is True
    assert request.idempotency_key == _KEY
    assert request.model_config["frozen"] is True

    for value in (False,):
        with pytest.raises(ValidationError):
            LabExecuteRequest(confirmed=value, idempotency_key=_KEY)
    with pytest.raises(ValidationError):
        LabExecuteRequest(confirmed=True, idempotency_key="not-a-uuid")
    for field in ("action", "url", "command", "credential"):
        with pytest.raises(ValidationError):
            LabExecuteRequest(confirmed=True, idempotency_key=_KEY, **{field: "x"})


def test_execution_records_are_frozen_and_use_the_internal_tool_ids() -> None:
    execution = _execution()

    assert {tool.value for tool in LabToolId} == {
        "gateway_enforcement",
        "security_case",
        "evidence_bundle",
    }
    with pytest.raises(ValidationError):
        execution.status = "failed"  # type: ignore[misc]


def test_execution_exposes_an_immutable_source_action_anchor() -> None:
    execution = _execution()

    assert execution.source_action == "block"
    with pytest.raises(ValidationError, match="cannot be weaker"):
        _execution(source_action="block", effective_action="allow")


def test_legacy_tool_input_serializes_only_the_new_tool_id() -> None:
    execution = _execution(tool_id="gateway_preview")

    assert execution.tool_id is LabToolId.GATEWAY_ENFORCEMENT
    assert execution.model_dump(mode="json")["tool_id"] == "gateway_enforcement"


@pytest.mark.parametrize(
    "factory, forbidden_key",
    [
        (_execution, "prompt"),
        (_security_case, "suffix"),
        (_artifact, "raw_output"),
        (_artifact, "query_text"),
        (_execution, "token_id"),
    ],
)
def test_persistent_records_reject_forbidden_public_fields(
    factory: object, forbidden_key: str
) -> None:
    with pytest.raises(ValidationError):
        factory(**{forbidden_key: "secret"})  # type: ignore[operator]


def test_artifact_json_never_serializes_its_internal_payload() -> None:
    artifact = _artifact()

    public_json = artifact.model_dump(mode="json")

    assert "payload" not in public_json
    assert public_json["sha256"] == "sha256:" + "b" * 64


@pytest.mark.parametrize(
    "payload",
    [
        b"raw prompt: secret",
        b'["evidence"]',
        b'{"prompt":"secret"}',
        b'{"receipt":"receipt-001", "decision":"block"}',
    ],
)
def test_artifact_payload_requires_canonical_redacted_json_object(
    payload: bytes,
) -> None:
    with pytest.raises(ValidationError):
        _artifact(payload=payload)


def test_persisted_created_at_requires_timezone_and_normalizes_to_utc() -> None:
    with pytest.raises(ValidationError):
        _artifact(created_at=datetime(2026, 8, 28, 8, 0))

    artifact = _artifact(
        created_at=datetime(2026, 8, 28, 10, 0, tzinfo=timezone(timedelta(hours=2)))
    )

    assert artifact.created_at == datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
