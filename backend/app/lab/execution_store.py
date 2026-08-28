from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from uuid import UUID

from app.lab.execution_models import (
    LabArtifact,
    LabSecurityCase,
    LabToolExecution,
)
from app.lab.models import LabToolId, assert_public_payload


_EXECUTION_COLUMNS = (
    "execution_id, run_id, tool_id, idempotency_key, status, effective_action, "
    "receipt_id, artifact_id, error_code, evidence_sha256, latency_ms, created_at"
)
_CASE_COLUMNS = (
    "case_id, run_id, created_at, risk_score, semantic_severity, "
    "semantic_categories, detector_status, anomaly_char_start, fusion_reason, "
    "effective_action, handling_status, knowledge_ids, model_id, "
    "calibration_version, knowledge_snapshot_version, execution_id, receipt_id"
)
_ARTIFACT_COLUMNS = (
    "artifact_id, run_id, execution_id, media_type, payload, sha256, created_at"
)


class SQLiteLabExecutionStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._create_schema()

    def get_by_idempotency(
        self, run_id: str, tool_id: LabToolId, idempotency_key: UUID
    ) -> LabToolExecution | None:
        with self._lock:
            row = self._connection.execute(
                f"SELECT {_EXECUTION_COLUMNS} FROM lab_tool_executions "
                "WHERE run_id = ? AND tool_id = ? AND idempotency_key = ?",
                (run_id, tool_id.value, str(idempotency_key)),
            ).fetchone()
        return None if row is None else _execution_from_row(row)

    def commit_result(
        self,
        execution: LabToolExecution,
        *,
        security_case: LabSecurityCase | None = None,
        artifact: LabArtifact | None = None,
    ) -> LabToolExecution:
        _validate_result(execution, security_case, artifact)
        with self._transaction():
            existing = self._get_by_idempotency_unlocked(
                execution.run_id, execution.tool_id, execution.idempotency_key
            )
            if existing is not None:
                return existing
            self._insert_execution(execution)
            if security_case is not None:
                self._insert_security_case(security_case)
            if artifact is not None:
                self._insert_artifact(artifact)
        return execution

    def list_executions(self, run_id: str) -> tuple[LabToolExecution, ...]:
        with self._lock:
            rows = self._connection.execute(
                f"SELECT {_EXECUTION_COLUMNS} FROM lab_tool_executions "
                "WHERE run_id = ? ORDER BY created_at DESC, execution_id DESC",
                (run_id,),
            ).fetchall()
        return tuple(_execution_from_row(row) for row in rows)

    def get_artifact(self, artifact_id: str) -> LabArtifact:
        with self._lock:
            row = self._connection.execute(
                f"SELECT {_ARTIFACT_COLUMNS} FROM lab_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            raise LookupError(artifact_id)
        return _artifact_from_row(row)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS lab_tool_executions (
                execution_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL,
                effective_action TEXT NOT NULL,
                receipt_id TEXT,
                artifact_id TEXT,
                error_code TEXT,
                evidence_sha256 TEXT,
                latency_ms REAL NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(run_id, tool_id, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS lab_security_cases (
                case_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                risk_score REAL NOT NULL,
                semantic_severity TEXT NOT NULL,
                semantic_categories TEXT NOT NULL,
                detector_status TEXT NOT NULL,
                anomaly_char_start INTEGER,
                fusion_reason TEXT NOT NULL,
                effective_action TEXT NOT NULL,
                handling_status TEXT NOT NULL,
                knowledge_ids TEXT NOT NULL,
                model_id TEXT NOT NULL,
                calibration_version TEXT NOT NULL,
                knowledge_snapshot_version TEXT,
                execution_id TEXT NOT NULL UNIQUE,
                receipt_id TEXT,
                FOREIGN KEY (execution_id)
                    REFERENCES lab_tool_executions(execution_id)
            );
            CREATE TABLE IF NOT EXISTS lab_artifacts (
                artifact_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                media_type TEXT NOT NULL,
                payload BLOB NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (execution_id)
                    REFERENCES lab_tool_executions(execution_id)
            );
            CREATE INDEX IF NOT EXISTS idx_lab_tool_executions_run_created
                ON lab_tool_executions(run_id, created_at DESC, execution_id DESC);
            """
        )
        self._connection.commit()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._connection.execute("BEGIN")
            try:
                yield
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _get_by_idempotency_unlocked(
        self, run_id: str, tool_id: LabToolId, idempotency_key: UUID
    ) -> LabToolExecution | None:
        row = self._connection.execute(
            f"SELECT {_EXECUTION_COLUMNS} FROM lab_tool_executions "
            "WHERE run_id = ? AND tool_id = ? AND idempotency_key = ?",
            (run_id, tool_id.value, str(idempotency_key)),
        ).fetchone()
        return None if row is None else _execution_from_row(row)

    def _insert_execution(self, execution: LabToolExecution) -> None:
        values = execution.model_dump(mode="json")
        self._connection.execute(
            f"INSERT INTO lab_tool_executions ({_EXECUTION_COLUMNS}) "
            f"VALUES ({', '.join('?' for _ in values)})",
            tuple(values.values()),
        )

    def _insert_security_case(self, security_case: LabSecurityCase) -> None:
        values = security_case.model_dump(mode="json")
        values["semantic_categories"] = _json_array(values["semantic_categories"])
        values["knowledge_ids"] = _json_array(values["knowledge_ids"])
        self._connection.execute(
            f"INSERT INTO lab_security_cases ({_CASE_COLUMNS}) "
            f"VALUES ({', '.join('?' for _ in values)})",
            tuple(values.values()),
        )

    def _insert_artifact(self, artifact: LabArtifact) -> None:
        values = artifact.model_dump(mode="json")
        values["payload"] = sqlite3.Binary(artifact.payload)
        ordered_values = tuple(values[column] for column in _ARTIFACT_COLUMNS.split(", "))
        self._connection.execute(
            f"INSERT INTO lab_artifacts ({_ARTIFACT_COLUMNS}) "
            f"VALUES ({', '.join('?' for _ in ordered_values)})",
            ordered_values,
        )


def _validate_result(
    execution: LabToolExecution,
    security_case: LabSecurityCase | None,
    artifact: LabArtifact | None,
) -> None:
    assert_public_payload(execution)
    if security_case is not None:
        assert_public_payload(security_case)
        if (
            security_case.run_id != execution.run_id
            or security_case.execution_id != execution.execution_id
            or security_case.receipt_id != execution.receipt_id
        ):
            raise ValueError("security case must belong to the execution")
    if artifact is not None:
        assert_public_payload(artifact)
        if (
            artifact.run_id != execution.run_id
            or artifact.execution_id != execution.execution_id
            or artifact.artifact_id != execution.artifact_id
        ):
            raise ValueError("artifact must belong to the execution")


def _json_array(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _execution_from_row(row: sqlite3.Row) -> LabToolExecution:
    return LabToolExecution.model_validate(dict(row))


def _artifact_from_row(row: sqlite3.Row) -> LabArtifact:
    values = dict(row)
    values["payload"] = bytes(values["payload"])
    return LabArtifact.model_validate(values)
