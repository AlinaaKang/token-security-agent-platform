from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import ValidationError

from app.security_agent.models import AgentEvent, AgentTaskSnapshot


class AgentStoreError(RuntimeError):
    """Base class for public task-store failures."""


class AgentTaskNotFound(AgentStoreError):
    pass


class AgentTaskConflict(AgentStoreError):
    pass


class AgentTaskCorrupt(AgentStoreError):
    pass


class AgentStoreClosed(AgentStoreError):
    pass


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SecurityAgentStore:
    def __init__(
        self,
        database_path: Path,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._lock = RLock()
        self._closed = False
        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = NORMAL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS agent_tasks (
                task_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_events (
                task_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                PRIMARY KEY (task_id, sequence),
                FOREIGN KEY (task_id) REFERENCES agent_tasks(task_id) ON DELETE CASCADE
            );
            """
        )

    @property
    def connection(self) -> sqlite3.Connection:
        self._ensure_open()
        return self._connection

    def create(self, snapshot: AgentTaskSnapshot | dict[str, Any]) -> AgentTaskSnapshot:
        validated = AgentTaskSnapshot.model_validate(snapshot)
        self._validate_events(validated)
        encoded = validated.model_dump_json()
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO agent_tasks(
                        task_id, version, status, created_at, updated_at, snapshot_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        validated.task_id,
                        validated.version,
                        validated.status.value,
                        validated.created_at,
                        validated.updated_at,
                        encoded,
                    ),
                )
                self._insert_events(validated.events)
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._rollback()
                raise AgentTaskConflict(f"task already exists: {validated.task_id}") from exc
            except Exception:
                self._rollback()
                raise
        return validated

    def replace(
        self,
        snapshot: AgentTaskSnapshot | dict[str, Any],
        *,
        expected_version: int,
    ) -> AgentTaskSnapshot:
        validated = AgentTaskSnapshot.model_validate(snapshot)
        self._validate_events(validated)
        if validated.version != expected_version + 1:
            raise AgentTaskConflict("replacement version must increment expected version by one")
        encoded = validated.model_dump_json()
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._connection.execute(
                    """
                    UPDATE agent_tasks
                    SET version = ?, status = ?, updated_at = ?, snapshot_json = ?
                    WHERE task_id = ? AND version = ?
                    """,
                    (
                        validated.version,
                        validated.status.value,
                        validated.updated_at,
                        encoded,
                        validated.task_id,
                        expected_version,
                    ),
                )
                if cursor.rowcount != 1:
                    exists = self._connection.execute(
                        "SELECT 1 FROM agent_tasks WHERE task_id = ?",
                        (validated.task_id,),
                    ).fetchone()
                    self._rollback()
                    if exists is None:
                        raise AgentTaskNotFound(validated.task_id)
                    raise AgentTaskConflict(
                        f"stale task version for {validated.task_id}: {expected_version}"
                    )
                self._connection.execute(
                    "DELETE FROM agent_events WHERE task_id = ?",
                    (validated.task_id,),
                )
                self._insert_events(validated.events)
                self._connection.execute("COMMIT")
            except (AgentTaskConflict, AgentTaskNotFound):
                raise
            except Exception:
                self._rollback()
                raise
        return validated

    def get(self, task_id: str) -> AgentTaskSnapshot:
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT snapshot_json FROM agent_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if row is None:
            raise AgentTaskNotFound(task_id)
        return self._decode_snapshot(row["snapshot_json"], task_id)

    def list(self, *, limit: int, offset: int) -> tuple[AgentTaskSnapshot, ...]:
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be non-negative")
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                """
                SELECT task_id, snapshot_json
                FROM agent_tasks
                ORDER BY rowid DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return tuple(
            self._decode_snapshot(row["snapshot_json"], row["task_id"])
            for row in rows
        )

    def events_after(self, task_id: str, sequence: int) -> tuple[AgentEvent, ...]:
        if sequence < 0:
            raise ValueError("sequence must be non-negative")
        with self._lock:
            self._ensure_open()
            exists = self._connection.execute(
                "SELECT 1 FROM agent_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if exists is None:
                raise AgentTaskNotFound(task_id)
            rows = self._connection.execute(
                """
                SELECT event_json
                FROM agent_events
                WHERE task_id = ? AND sequence > ?
                ORDER BY sequence ASC
                """,
                (task_id, sequence),
            ).fetchall()
        events: list[AgentEvent] = []
        for row in rows:
            try:
                events.append(AgentEvent.model_validate_json(row["event_json"]))
            except (ValidationError, ValueError, TypeError) as exc:
                raise AgentTaskCorrupt(f"invalid event data for task {task_id}") from exc
        return tuple(events)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def _insert_events(self, events: tuple[AgentEvent, ...]) -> None:
        self._connection.executemany(
            "INSERT INTO agent_events(task_id, sequence, event_json) VALUES (?, ?, ?)",
            [
                (event.task_id, event.sequence, event.model_dump_json())
                for event in events
            ],
        )

    @staticmethod
    def _validate_events(snapshot: AgentTaskSnapshot) -> None:
        previous = 0
        for event in snapshot.events:
            if event.task_id != snapshot.task_id:
                raise AgentTaskConflict("event task id does not match snapshot task id")
            if event.sequence <= previous:
                raise AgentTaskConflict("event sequence must be strictly monotonic")
            previous = event.sequence

    @staticmethod
    def _decode_snapshot(encoded: str, task_id: str) -> AgentTaskSnapshot:
        try:
            raw = json.loads(encoded)
            return AgentTaskSnapshot.model_validate(raw)
        except (json.JSONDecodeError, ValidationError, ValueError, TypeError) as exc:
            raise AgentTaskCorrupt(f"invalid task data for {task_id}") from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentStoreClosed("security agent store is closed")

    def _rollback(self) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")

