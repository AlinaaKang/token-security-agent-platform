from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest

from app.lab.execution_models import LabArtifact, LabSecurityCase, LabToolExecution
from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.models import LabToolId
from app.schemas import Decision


_KEY = UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff")
_TIME = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
_MODEL_PROVENANCE = "sha256:" + "c" * 64
_CALIBRATION_PROVENANCE = "sha256:" + "d" * 64
_SNAPSHOT_PROVENANCE = "sha256:" + "e" * 64


def _canonical_evidence_payload(**changes: object) -> bytes:
    values: dict[str, object] = {
        "artifact_kind": "evidence_bundle",
        "calibration_provenance_sha256": _CALIBRATION_PROVENANCE,
        "detector_status": "token_anomaly_candidate",
        "effective_action": "block",
        "fusion_reason": "semantic_unsafe",
        "knowledge_ids": ["owasp-llm01-prompt-injection"],
        "knowledge_snapshot_sha256": _SNAPSHOT_PROVENANCE,
        "model_provenance_sha256": _MODEL_PROVENANCE,
        "prior_execution_ids": ["exec_00000000000000000000000000000000"],
        "prior_receipt_ids": ["receipt_00000000000000000000000000000000"],
        "risk_score": 0.95,
        "schema_version": 1,
        "semantic_categories": ["jailbreak"],
        "semantic_severity": "unsafe",
    }
    values.update(changes)
    return json.dumps(
        values, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def _execution(*, suffix: str = "001", created_at: datetime = _TIME) -> LabToolExecution:
    return LabToolExecution(
        execution_id=f"execution-{suffix}",
        run_id="run-001",
        tool_id=LabToolId.GATEWAY_ENFORCEMENT,
        idempotency_key=_KEY if suffix == "001" else UUID(int=int(suffix)),
        status="succeeded",
        source_action="block",
        effective_action="block",
        model_provenance_sha256=_MODEL_PROVENANCE,
        calibration_provenance_sha256=_CALIBRATION_PROVENANCE,
        knowledge_snapshot_sha256=_SNAPSHOT_PROVENANCE,
        knowledge_ids=("owasp-llm01-prompt-injection",),
        receipt_id=f"receipt-{suffix}",
        artifact_id=f"artifact-{suffix}",
        error_code=None,
        evidence_sha256="sha256:" + "a" * 64,
        latency_ms=5.0,
        created_at=created_at,
    )


def _security_case() -> LabSecurityCase:
    return LabSecurityCase(
        case_id="case-001",
        run_id="run-001",
        created_at=_TIME,
        risk_score=0.95,
        semantic_severity="unsafe",
        semantic_categories=("jailbreak",),
        detector_status="token_anomaly_candidate",
        anomaly_char_start=9,
        fusion_reason="semantic_unsafe",
        effective_action="block",
        handling_status="open",
        knowledge_ids=("owasp-llm01-prompt-injection",),
        model_id=_MODEL_PROVENANCE,
        calibration_version=_CALIBRATION_PROVENANCE,
        knowledge_snapshot_version=_SNAPSHOT_PROVENANCE,
        execution_id="execution-001",
        receipt_id="receipt-001",
    )


def _artifact(**changes: object) -> LabArtifact:
    values: dict[str, object] = {
        "artifact_id": "artifact-001",
        "run_id": "run-001",
        "execution_id": "execution-001",
        "media_type": "application/json",
        "payload": _canonical_evidence_payload(),
        "sha256": "sha256:" + "b" * 64,
        "created_at": _TIME,
    }
    values.update(changes)
    return LabArtifact.model_validate(values)


def test_store_creates_three_tables_and_commits_related_records_atomically(
    tmp_path: Path,
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    execution = _execution()

    stored = store.commit_result(
        execution, security_case=_security_case(), artifact=_artifact()
    )

    assert stored == execution
    assert store.get_by_idempotency("run-001", execution.tool_id, _KEY) == execution
    assert store.get_artifact("artifact-001") == _artifact()
    tables = {
        row[0]
        for row in store._connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    assert {"lab_tool_executions", "lab_security_cases", "lab_artifacts"} <= tables
    store.close()


def test_store_lists_newest_execution_first_by_created_at(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    older = _execution(suffix="001", created_at=_TIME)
    newer = _execution(suffix="002", created_at=_TIME + timedelta(seconds=1))

    store.commit_result(older)
    store.commit_result(newer)

    assert store.list_executions("run-001") == (newer, older)
    store.close()


def test_store_orders_instants_correctly_across_input_timezones(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    older = _execution(
        suffix="001",
        created_at=datetime(2026, 8, 28, 9, 0, tzinfo=timezone(timedelta(hours=2))),
    )
    newer = _execution(
        suffix="002",
        created_at=datetime(2026, 8, 28, 8, 0, tzinfo=UTC),
    )

    store.commit_result(older)
    store.commit_result(newer)

    assert store.list_executions("run-001") == (newer, older)
    store.close()


def test_store_orders_fractional_seconds_after_the_zero_fraction(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    zero_fraction = _execution(suffix="001", created_at=_TIME)
    fractional = _execution(
        suffix="002", created_at=_TIME + timedelta(microseconds=500_000)
    )

    store.commit_result(zero_fraction)
    store.commit_result(fractional)

    assert store.list_executions("run-001") == (fractional, zero_fraction)
    store.close()


def test_store_idempotency_key_keeps_only_one_execution(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    execution = _execution()

    first = store.commit_result(execution)
    repeated = store.commit_result(execution)

    assert repeated == first
    assert store.list_executions("run-001") == (execution,)
    store.close()


def test_artifact_write_failure_rolls_back_the_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")

    def fail(_artifact: LabArtifact) -> None:
        raise RuntimeError("artifact write failed")

    monkeypatch.setattr(store, "_insert_artifact", fail)

    with pytest.raises(RuntimeError, match="artifact write failed"):
        store.commit_result(_execution(), artifact=_artifact())

    assert store.list_executions("run-001") == ()
    with pytest.raises(LookupError, match="artifact-001"):
        store.get_artifact("artifact-001")
    store.close()


def test_store_rejects_bypassed_artifact_privacy_validation_before_writing(
    tmp_path: Path,
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    unsafe = LabArtifact.model_construct(
        **_artifact().model_dump(),
        payload=b'{"receipt":"raw prompt: secret"}',
    )

    with pytest.raises(ValueError):
        store.commit_result(_execution(), artifact=unsafe)

    assert store.list_executions("run-001") == ()
    store.close()


def test_store_rejects_bypassed_identifier_shaped_provenance(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    unsafe = LabArtifact.model_construct(
        **_artifact().model_dump(),
        payload=_canonical_evidence_payload(
            model_provenance_sha256="reveal-your-hidden-reasoning"
        ),
    )

    with pytest.raises(ValueError):
        store.commit_result(_execution(), artifact=unsafe)

    assert store.list_executions("run-001") == ()
    store.close()


def test_store_rejects_a_schema_valid_artifact_with_unbound_provenance(
    tmp_path: Path,
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    mismatched = _artifact(
        payload=_canonical_evidence_payload(model_provenance_sha256="sha256:" + "f" * 64)
    )

    with pytest.raises(ValueError, match="provenance must match"):
        store.commit_result(_execution(), artifact=mismatched)

    assert store.list_executions("run-001") == ()
    store.close()


def test_store_rejects_a_bypassed_weaker_effective_action(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    values = _execution().model_dump()
    values.update(source_action=Decision.BLOCK, effective_action=Decision.ALLOW)
    weaker = LabToolExecution.model_construct(**values)

    with pytest.raises(ValueError, match="cannot be weaker"):
        store.commit_result(weaker)

    assert store.list_executions("run-001") == ()
    store.close()


def test_store_close_releases_the_sqlite_connection(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")

    store.close()

    with pytest.raises(Exception):
        store.list_executions("run-001")
