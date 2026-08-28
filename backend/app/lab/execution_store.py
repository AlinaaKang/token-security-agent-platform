from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator
from uuid import UUID

from app.lab.execution_models import (
    LabArtifact,
    LabSecurityCase,
    LabToolExecution,
    normalize_persisted_created_at,
    parse_canonical_evidence_bundle,
)
from app.lab.models import LabToolId, assert_public_payload, safer_action


_EXECUTION_COLUMNS = (
    "execution_id, run_id, tool_id, idempotency_key, status, source_action, "
    "effective_action, model_provenance_sha256, calibration_provenance_sha256, "
    "knowledge_snapshot_sha256, knowledge_ids, "
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
_SCHEMA_VERSION = 1
_SCHEMA_TABLE = "lab_execution_schema"
_TABLE_COLUMNS = {
    "lab_tool_executions": tuple(_EXECUTION_COLUMNS.split(", ")),
    "lab_security_cases": tuple(_CASE_COLUMNS.split(", ")),
    "lab_artifacts": tuple(_ARTIFACT_COLUMNS.split(", ")),
    _SCHEMA_TABLE: ("schema_version",),
}
_UNSUPPORTED_SCHEMA_MESSAGE = "lab execution store schema is unsupported"


class UnsupportedLabExecutionSchemaError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(_UNSUPPORTED_SCHEMA_MESSAGE)


class SQLiteLabExecutionStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        try:
            with self._lock:
                self._connection.execute("PRAGMA foreign_keys = ON")
                self._initialize_schema()
        except BaseException:
            self._connection.close()
            raise

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

    def _initialize_schema(self) -> None:
        existing_tables = {
            row[0]
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
            if row[0] in _TABLE_COLUMNS
        }
        if not existing_tables:
            self._create_schema()
            return
        if existing_tables != set(_TABLE_COLUMNS):
            raise UnsupportedLabExecutionSchemaError
        for table, expected_columns in _TABLE_COLUMNS.items():
            actual_columns = tuple(
                row[1]
                for row in self._connection.execute(f"PRAGMA table_info({table})")
            )
            if actual_columns != expected_columns:
                raise UnsupportedLabExecutionSchemaError
        versions = tuple(
            row[0]
            for row in self._connection.execute(
                f"SELECT schema_version FROM {_SCHEMA_TABLE}"
            )
        )
        if versions != (_SCHEMA_VERSION,):
            raise UnsupportedLabExecutionSchemaError

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE lab_execution_schema (
                schema_version INTEGER PRIMARY KEY
            );
            INSERT INTO lab_execution_schema (schema_version) VALUES (1);
            CREATE TABLE IF NOT EXISTS lab_tool_executions (
                execution_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL,
                source_action TEXT NOT NULL,
                effective_action TEXT NOT NULL,
                model_provenance_sha256 TEXT NOT NULL,
                calibration_provenance_sha256 TEXT NOT NULL,
                knowledge_snapshot_sha256 TEXT,
                knowledge_ids TEXT NOT NULL,
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
        values["created_at"] = _serialized_created_at(execution.created_at)
        values["knowledge_ids"] = _json_array(values["knowledge_ids"])
        self._connection.execute(
            f"INSERT INTO lab_tool_executions ({_EXECUTION_COLUMNS}) "
            f"VALUES ({', '.join('?' for _ in values)})",
            tuple(values.values()),
        )

    def _insert_security_case(self, security_case: LabSecurityCase) -> None:
        values = security_case.model_dump(mode="json")
        values["created_at"] = _serialized_created_at(security_case.created_at)
        values["semantic_categories"] = _json_array(values["semantic_categories"])
        values["knowledge_ids"] = _json_array(values["knowledge_ids"])
        self._connection.execute(
            f"INSERT INTO lab_security_cases ({_CASE_COLUMNS}) "
            f"VALUES ({', '.join('?' for _ in values)})",
            tuple(values.values()),
        )

    def _insert_artifact(self, artifact: LabArtifact) -> None:
        values = artifact.model_dump(mode="json")
        values["created_at"] = _serialized_created_at(artifact.created_at)
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
    if execution.effective_action != safer_action(
        execution.source_action, execution.effective_action
    ):
        raise ValueError("effective_action cannot be weaker than source_action")
    normalize_persisted_created_at(execution.created_at)
    if security_case is not None:
        assert_public_payload(security_case)
        normalize_persisted_created_at(security_case.created_at)
        if (
            security_case.run_id != execution.run_id
            or security_case.execution_id != execution.execution_id
            or security_case.receipt_id != execution.receipt_id
            or security_case.effective_action != execution.effective_action
        ):
            raise ValueError("security case must belong to the execution")
        if (
            security_case.model_id != execution.model_provenance_sha256
            or security_case.calibration_version
            != execution.calibration_provenance_sha256
            or security_case.knowledge_snapshot_version
            != execution.knowledge_snapshot_sha256
            or security_case.knowledge_ids != execution.knowledge_ids
        ):
            raise ValueError("security case provenance must match the execution")
    if artifact is not None:
        assert_public_payload(artifact)
        bundle = parse_canonical_evidence_bundle(
            artifact.media_type, artifact.payload
        )
        normalize_persisted_created_at(artifact.created_at)
        if (
            artifact.run_id != execution.run_id
            or artifact.execution_id != execution.execution_id
            or artifact.artifact_id != execution.artifact_id
        ):
            raise ValueError("artifact must belong to the execution")
        if (
            bundle.model_provenance_sha256 != execution.model_provenance_sha256
            or bundle.calibration_provenance_sha256
            != execution.calibration_provenance_sha256
            or bundle.knowledge_snapshot_sha256
            != execution.knowledge_snapshot_sha256
            or bundle.knowledge_ids != execution.knowledge_ids
        ):
            raise ValueError("artifact provenance must match the execution")
        if bundle.effective_action != execution.effective_action:
            raise ValueError("artifact action must match the execution")


def _json_array(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _serialized_created_at(value: object) -> str:
    if not isinstance(value, datetime):
        raise ValueError("persisted created_at must be a datetime")
    return (
        normalize_persisted_created_at(value)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _execution_from_row(row: sqlite3.Row) -> LabToolExecution:
    values = dict(row)
    values["knowledge_ids"] = json.loads(values["knowledge_ids"])
    return LabToolExecution.model_validate(values)


def _artifact_from_row(row: sqlite3.Row) -> LabArtifact:
    values = dict(row)
    values["payload"] = bytes(values["payload"])
    return LabArtifact.model_validate(values)
