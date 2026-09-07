from __future__ import annotations

import sqlite3

import pytest

from app.security_agent.models import AgentEvent, AgentTaskSnapshot
from app.security_agent.store import (
    AgentStoreClosed,
    AgentTaskConflict,
    AgentTaskCorrupt,
    AgentTaskNotFound,
    SecurityAgentStore,
)


def event_payload(sequence: int, *, task_id: str = "task_" + "a" * 32) -> dict[str, object]:
    return {
        "task_id": task_id,
        "sequence": sequence,
        "phase": "plan",
        "kind": "plan_created",
        "summary": f"计划事件 {sequence}",
        "created_at": f"2026-09-07T08:00:{sequence:02d}Z",
        "evidence_refs": [],
    }


def snapshot_payload(
    *,
    task_id: str = "task_" + "a" * 32,
    version: int = 1,
    events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "task_id": task_id,
        "version": version,
        "task_type": "pcap_dataset_investigation",
        "status": "running",
        "title": "PCAP 调查",
        "objective_summary": "调查授权范围内的异常候选。",
        "created_at": "2026-09-07T08:00:00Z",
        "updated_at": f"2026-09-07T08:00:{version:02d}Z",
        "messages": [],
        "plan": [],
        "observations": [],
        "evidence": [],
        "hypotheses": [],
        "timeline": [],
        "conflicts": [],
        "events": events or [],
        "replan_count": 0,
        "authorization_scopes": [],
        "final_status": None,
        "report": None,
        "limitations": [],
    }


def test_store_restores_messages_plan_evidence_and_events(tmp_path) -> None:
    database_path = tmp_path / "agent.sqlite3"
    store = SecurityAgentStore(database_path)
    created = store.create(
        snapshot_payload(events=[event_payload(1), event_payload(2)])
    )
    store.close()

    reopened = SecurityAgentStore(database_path)
    restored = reopened.get(created.task_id)

    assert restored == created
    assert reopened.events_after(created.task_id, 0) == created.events


def test_store_rejects_stale_task_version(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    created = store.create(snapshot_payload())
    store.replace(
        created.model_copy(update={"version": 2, "updated_at": "2026-09-07T08:00:02Z"}),
        expected_version=1,
    )

    with pytest.raises(AgentTaskConflict):
        store.replace(
            created.model_copy(
                update={"version": 3, "updated_at": "2026-09-07T08:00:03Z"}
            ),
            expected_version=1,
        )


def test_store_uses_wal_and_foreign_keys(tmp_path) -> None:
    database_path = tmp_path / "agent.sqlite3"
    store = SecurityAgentStore(database_path)

    connection = sqlite3.connect(database_path)
    assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert store.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_store_lists_newest_tasks_with_pagination(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    for index in range(3):
        task_id = f"task_{index:032x}"
        store.create(snapshot_payload(task_id=task_id))

    first_page = store.list(limit=2, offset=0)
    second_page = store.list(limit=2, offset=2)

    assert [item.task_id for item in first_page] == [
        "task_00000000000000000000000000000002",
        "task_00000000000000000000000000000001",
    ]
    assert [item.task_id for item in second_page] == [
        "task_00000000000000000000000000000000"
    ]


def test_store_rejects_non_monotonic_event_sequences(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")

    with pytest.raises(AgentTaskConflict, match="monotonic"):
        store.create(snapshot_payload(events=[event_payload(2), event_payload(1)]))


def test_store_rejects_event_for_another_task(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")

    with pytest.raises(AgentTaskConflict, match="task id"):
        store.create(
            snapshot_payload(events=[event_payload(1, task_id="task_" + "b" * 32)])
        )


def test_store_rejects_malformed_stored_json(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    created = store.create(snapshot_payload())
    store.connection.execute(
        "UPDATE agent_tasks SET snapshot_json = ? WHERE task_id = ?",
        ("{not-json", created.task_id),
    )
    store.connection.commit()

    with pytest.raises(AgentTaskCorrupt):
        store.get(created.task_id)


def test_store_close_prevents_further_operations(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    store.close()

    with pytest.raises(AgentStoreClosed):
        store.list(limit=10, offset=0)


def test_store_reports_missing_tasks(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")

    with pytest.raises(AgentTaskNotFound):
        store.get("task_" + "f" * 32)


def test_store_delete_removes_task_and_events(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    created = store.create(snapshot_payload(events=[event_payload(1)]))

    store.delete(created.task_id)

    with pytest.raises(AgentTaskNotFound):
        store.get(created.task_id)
    assert store.connection.execute(
        "SELECT COUNT(*) FROM agent_events WHERE task_id = ?", (created.task_id,)
    ).fetchone()[0] == 0


def test_store_delete_reports_missing_task(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")

    with pytest.raises(AgentTaskNotFound):
        store.delete("task_" + "f" * 32)


def test_database_never_contains_rejected_private_sentinel(tmp_path) -> None:
    database_path = tmp_path / "agent.sqlite3"
    store = SecurityAgentStore(database_path)
    payload = snapshot_payload()
    payload["evidence"] = [
        {
            "evidence_id": "ev_private",
            "authenticity": "real",
            "source_type": "pcap_detection",
            "source_ref": "batch_01",
            "tool_id": "detect_pcap_batch",
            "summary": "公开摘要。",
            "observed_at": "2026-09-07T08:00:00Z",
            "uncertainty": "当前范围。",
            "metadata": {"payload": "PRIVATE_SENTINEL"},
        }
    ]

    with pytest.raises(ValueError):
        store.create(payload)
    store.close()
    assert b"PRIVATE_SENTINEL" not in database_path.read_bytes()


def test_events_after_returns_only_later_validated_events(tmp_path) -> None:
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    snapshot = AgentTaskSnapshot.model_validate(
        snapshot_payload(events=[event_payload(1), event_payload(2), event_payload(3)])
    )
    store.create(snapshot)

    events = store.events_after(snapshot.task_id, 1)

    assert events == (
        AgentEvent.model_validate(event_payload(2)),
        AgentEvent.model_validate(event_payload(3)),
    )
