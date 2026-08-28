from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from app.lab.execution_models import LabArtifact, LabSecurityCase, LabToolExecution
from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.models import LabToolId


_KEY = UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff")
_TIME = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)


def _execution(*, suffix: str = "001", created_at: datetime = _TIME) -> LabToolExecution:
    return LabToolExecution(
        execution_id=f"execution-{suffix}",
        run_id="run-001",
        tool_id=LabToolId.GATEWAY_ENFORCEMENT,
        idempotency_key=_KEY if suffix == "001" else UUID(int=int(suffix)),
        status="succeeded",
        effective_action="block",
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
        model_id="semantic-guard-v1",
        calibration_version="2026-08",
        knowledge_snapshot_version="2026-08-28",
        execution_id="execution-001",
        receipt_id="receipt-001",
    )


def _artifact() -> LabArtifact:
    return LabArtifact(
        artifact_id="artifact-001",
        run_id="run-001",
        execution_id="execution-001",
        media_type="application/json",
        payload=b'{"receipt":"receipt-001"}',
        sha256="sha256:" + "b" * 64,
        created_at=_TIME,
    )


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


def test_store_close_releases_the_sqlite_connection(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")

    store.close()

    with pytest.raises(Exception):
        store.list_executions("run-001")
