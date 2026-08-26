from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3

from app.audit.models import SecurityEvent
from app.audit.store import SQLiteEventStore


def make_event(
    request_id: str,
    *,
    created_at: datetime,
    decision: str = "review",
    detector_status: str = "token_anomaly_candidate",
    semantic_severity: str | None = "unsafe",
    semantic_categories: list[str] | None = None,
    knowledge_card_ids: list[str] | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        request_id=request_id,
        created_at=created_at,
        prompt_sha256="sha256:" + "a" * 64,
        prompt_char_count=19,
        token_count=4,
        detector_score=5.0,
        k=0.0,
        h=1.7,
        onset_token=2,
        detector_status=detector_status,
        decision=decision,
        mode="analysis",
        model_id="qwen-model",
        calibration_version="cal-v1",
        latency_ms=12.5,
        semantic_severity=semantic_severity,
        semantic_categories=(semantic_categories or ["violent"]),
        semantic_model_id="guard-model" if semantic_severity else None,
        semantic_model_version="guard-v1" if semantic_severity else None,
        semantic_latency_ms=2.0 if semantic_severity else None,
        fusion_reason="semantic_unsafe" if semantic_severity else None,
        knowledge_snapshot_version="official-v1" if knowledge_card_ids else None,
        knowledge_mode="report" if knowledge_card_ids else None,
        knowledge_status="ready" if knowledge_card_ids else None,
        knowledge_card_ids=knowledge_card_ids,
        report_status="generated" if knowledge_card_ids else None,
        knowledge_latency_ms=3.5 if knowledge_card_ids else None,
    )


def test_event_store_pages_filters_and_never_persists_prompt_text() -> None:
    database_path = Path("tmp/test-security-events.sqlite3")
    database_path.unlink(missing_ok=True)
    store = SQLiteEventStore(database_path)
    started = datetime(2026, 8, 25, 8, 0, tzinfo=UTC)
    try:
        store.append(make_event("req-1", created_at=started, decision="allow", detector_status="no_token_anomaly"))
        store.append(make_event("req-2", created_at=started + timedelta(seconds=1)))
        store.append(make_event("req-3", created_at=started + timedelta(seconds=2)))

        first_page = store.list_events(limit=2, offset=0)
        reviews = store.list_events(limit=10, offset=0, decision="review")
    finally:
        store.close()

    assert first_page.total == 3
    assert [event.request_id for event in first_page.items] == ["req-3", "req-2"]
    assert [event.request_id for event in reviews.items] == ["req-3", "req-2"]
    database_bytes = database_path.read_bytes()
    assert b"SAFE_PRIVATE_PROMPT" not in database_bytes
    assert b"token_text" not in database_bytes
    assert b"guard_raw_output" not in database_bytes
    assert b"Safety: Unsafe" not in database_bytes
    database_path.unlink(missing_ok=True)


def test_event_store_migrates_legacy_schema_without_deleting_rows() -> None:
    database_path = Path("tmp/test-security-events-legacy.sqlite3")
    database_path.unlink(missing_ok=True)
    connection = sqlite3.connect(database_path)
    connection.execute(
        """
        CREATE TABLE security_events (
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
    connection.execute(
        "INSERT INTO security_events VALUES "
        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "legacy-1",
            "2026-08-25T08:00:00+00:00",
            "sha256:" + "b" * 64,
            10,
            3,
            0.0,
            0.0,
            1.7,
            None,
            "no_token_anomaly",
            "allow",
            "analysis",
            "qwen-model",
            "cal-v1",
            8.0,
        ),
    )
    connection.commit()
    connection.close()

    store = SQLiteEventStore(database_path)
    try:
        legacy = store.list_events(limit=10, offset=0).items[0]
        store.append(
            make_event(
                "new-1",
                created_at=datetime(2026, 8, 25, 9, 0, tzinfo=UTC),
                semantic_categories=["violent", "jailbreak"],
            )
        )
        new_event = store.list_events(limit=10, offset=0).items[0]
    finally:
        store.close()

    second_store = SQLiteEventStore(database_path)
    second_store.close()

    assert legacy.request_id == "legacy-1"
    assert legacy.semantic_severity is None
    assert legacy.semantic_categories is None
    assert new_event.semantic_severity == "unsafe"
    assert new_event.semantic_categories == ["jailbreak", "violent"]
    assert new_event.fusion_reason == "semantic_unsafe"

    connection = sqlite3.connect(database_path)
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(security_events)")
    }
    connection.close()
    assert {
        "semantic_severity",
        "semantic_categories",
        "semantic_model_id",
        "semantic_model_version",
        "semantic_latency_ms",
        "fusion_reason",
        "knowledge_snapshot_version",
        "knowledge_mode",
        "knowledge_status",
        "knowledge_card_ids",
        "report_status",
        "knowledge_latency_ms",
    } <= columns
    database_path.unlink(missing_ok=True)


def test_event_store_persists_only_normalized_knowledge_metadata() -> None:
    database_path = Path("tmp/test-security-events-knowledge.sqlite3")
    database_path.unlink(missing_ok=True)
    store = SQLiteEventStore(database_path)
    try:
        store.append(
            make_event(
                "knowledge-1",
                created_at=datetime(2026, 8, 26, 10, 0, tzinfo=UTC),
                knowledge_card_ids=[
                    "owasp-llm01-prompt-injection",
                    "mitre-atlas-jailbreak",
                    "owasp-llm01-prompt-injection",
                ],
            )
        )
        event = store.list_events(limit=10, offset=0).items[0]
    finally:
        store.close()

    assert event.knowledge_card_ids == [
        "mitre-atlas-jailbreak",
        "owasp-llm01-prompt-injection",
    ]
    assert event.report_status == "generated"
    assert event.knowledge_latency_ms == 3.5
    database_bytes = database_path.read_bytes()
    for forbidden in (
        b"SAFE_PRIVATE_QUERY",
        b"knowledge card private summary",
        b"grounded report private body",
        b"raw_output",
    ):
        assert forbidden not in database_bytes
    database_path.unlink(missing_ok=True)
