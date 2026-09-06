from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.schemas import NonEmptyText


class AnalystFeedbackRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    feedback_id: str = Field(pattern=r"^feedback_[0-9a-f]{32}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9_-]{3,128}$")
    verdict: Literal["confirmed", "false_positive", "missed_detection", "inconclusive"]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    evidence_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=50)
    created_at: NonEmptyText


class AnalystFeedbackService:
    def __init__(
        self,
        database_path: Path,
        *,
        detector_identity: Callable[[], str],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_feedback (
              feedback_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              record_json TEXT NOT NULL
            )
            """
        )
        self._connection.commit()
        self._identity = detector_identity
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()

    def detector_identity(self) -> str:
        return self._identity()

    def record_feedback(
        self,
        *,
        task_id: str,
        verdict: Literal["confirmed", "false_positive", "missed_detection", "inconclusive"],
        reason_code: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> AnalystFeedbackRecord:
        record = AnalystFeedbackRecord(
            feedback_id=f"feedback_{uuid4().hex}",
            task_id=task_id,
            verdict=verdict,
            reason_code=reason_code,
            evidence_refs=evidence_refs,
            created_at=self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z"),
        )
        serialized = record.model_dump_json()
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO analyst_feedback(feedback_id, task_id, created_at, record_json) VALUES (?, ?, ?, ?)",
                (record.feedback_id, record.task_id, record.created_at, serialized),
            )
        return record

    def list_for_task(self, task_id: str) -> tuple[AnalystFeedbackRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM analyst_feedback WHERE task_id = ? ORDER BY created_at, feedback_id",
                (task_id,),
            ).fetchall()
        return tuple(
            AnalystFeedbackRecord.model_validate(json.loads(row[0])) for row in rows
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()
