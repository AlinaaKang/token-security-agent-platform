from __future__ import annotations

import sqlite3
import threading
import json
from pathlib import Path

from app.audit.models import EventPage, SecurityEvent
from app.schemas import Decision, DetectorStatus


_EVENT_COLUMNS = (
    "request_id, created_at, prompt_sha256, prompt_char_count, token_count, "
    "detector_score, k, h, onset_token, detector_status, decision, mode, "
    "model_id, calibration_version, latency_ms, semantic_severity, "
    "semantic_categories, semantic_model_id, semantic_model_version, "
    "semantic_latency_ms, fusion_reason, knowledge_snapshot_version, "
    "knowledge_mode, knowledge_status, knowledge_card_ids, report_status, "
    "knowledge_latency_ms"
)

_SEMANTIC_COLUMN_TYPES = {
    "semantic_severity": "TEXT",
    "semantic_categories": "TEXT",
    "semantic_model_id": "TEXT",
    "semantic_model_version": "TEXT",
    "semantic_latency_ms": "REAL",
    "fusion_reason": "TEXT",
}

_KNOWLEDGE_COLUMN_TYPES = {
    "knowledge_snapshot_version": "TEXT",
    "knowledge_mode": "TEXT",
    "knowledge_status": "TEXT",
    "knowledge_card_ids": "TEXT",
    "report_status": "TEXT",
    "knowledge_latency_ms": "REAL",
}


class SQLiteEventStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    request_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    prompt_sha256 TEXT NOT NULL,
                    prompt_char_count INTEGER NOT NULL,
                    token_count INTEGER NOT NULL,
                    detector_score REAL NOT NULL,
                    k REAL NOT NULL,
                    h REAL NOT NULL,
                    onset_token INTEGER,
                    detector_status TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    calibration_version TEXT NOT NULL,
                    latency_ms REAL NOT NULL
                )
                """
            )
            existing_columns = {
                row[1]
                for row in self._connection.execute(
                    "PRAGMA table_info(security_events)"
                )
            }
            for name, column_type in {
                **_SEMANTIC_COLUMN_TYPES,
                **_KNOWLEDGE_COLUMN_TYPES,
            }.items():
                if name not in existing_columns:
                    self._connection.execute(
                        f"ALTER TABLE security_events ADD COLUMN {name} {column_type}"
                    )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_created "
                "ON security_events(created_at DESC, request_id DESC)"
            )

    def append(self, event: SecurityEvent) -> None:
        values = event.model_dump(mode="json")
        categories = values["semantic_categories"]
        serialized_categories = (
            None
            if categories is None
            else json.dumps(sorted(categories), separators=(",", ":"))
        )
        card_ids = values["knowledge_card_ids"]
        serialized_card_ids = (
            None
            if card_ids is None
            else json.dumps(
                sorted(set(card_ids))[:3],
                separators=(",", ":"),
            )
        )
        parameters = (
            values["request_id"],
            values["created_at"],
            values["prompt_sha256"],
            values["prompt_char_count"],
            values["token_count"],
            values["detector_score"],
            values["k"],
            values["h"],
            values["onset_token"],
            values["detector_status"],
            values["decision"],
            values["mode"],
            values["model_id"],
            values["calibration_version"],
            values["latency_ms"],
            values["semantic_severity"],
            serialized_categories,
            values["semantic_model_id"],
            values["semantic_model_version"],
            values["semantic_latency_ms"],
            values["fusion_reason"],
            values["knowledge_snapshot_version"],
            values["knowledge_mode"],
            values["knowledge_status"],
            serialized_card_ids,
            values["report_status"],
            values["knowledge_latency_ms"],
        )
        with self._lock, self._connection:
            self._connection.execute(
                f"INSERT INTO security_events ({_EVENT_COLUMNS}) "
                f"VALUES ({', '.join('?' for _ in parameters)})",
                parameters,
            )

    def list_events(
        self,
        *,
        limit: int,
        offset: int,
        decision: Decision | str | None = None,
        detector_status: DetectorStatus | None = None,
    ) -> EventPage:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be non-negative")

        where: list[str] = []
        parameters: list[str | int] = []
        if decision is not None:
            normalized_decision = Decision(decision)
            where.append("decision = ?")
            parameters.append(normalized_decision.value)
        if detector_status is not None:
            where.append("detector_status = ?")
            parameters.append(detector_status)
        where_sql = f" WHERE {' AND '.join(where)}" if where else ""

        with self._lock:
            total = int(
                self._connection.execute(
                    f"SELECT COUNT(*) FROM security_events{where_sql}", parameters
                ).fetchone()[0]
            )
            rows = self._connection.execute(
                f"SELECT {_EVENT_COLUMNS} FROM security_events{where_sql} "
                "ORDER BY created_at DESC, request_id DESC LIMIT ? OFFSET ?",
                [*parameters, limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            payload = dict(row)
            if payload["semantic_categories"] is not None:
                payload["semantic_categories"] = json.loads(
                    payload["semantic_categories"]
                )
            if payload["knowledge_card_ids"] is not None:
                card_ids = json.loads(payload["knowledge_card_ids"])
                if not isinstance(card_ids, list) or len(card_ids) > 3:
                    raise ValueError("invalid audited knowledge card IDs")
                payload["knowledge_card_ids"] = card_ids
            items.append(SecurityEvent.model_validate(payload))
        return EventPage(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()
