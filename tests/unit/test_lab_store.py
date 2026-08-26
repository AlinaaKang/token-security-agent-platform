from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import BaseModel, ConfigDict

from app.lab.store import LabRunExpired, LabRunNotFound, LabRunStore


class StoredRun(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    status: str = "completed"
    evidence: dict[str, object] = {}


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_store_returns_the_same_redacted_completed_run() -> None:
    store = LabRunStore(capacity=2, ttl_seconds=15, clock=FakeClock())
    run = StoredRun(run_id="lab_1", evidence={"decision": "block"})

    store.put(run)

    assert store.get("lab_1") == run
    assert store.snapshot() == (run,)


def test_store_rejects_payloads_with_forbidden_fields_before_retention() -> None:
    store = LabRunStore(capacity=2, ttl_seconds=15, clock=FakeClock())
    unsafe = StoredRun(run_id="lab_1", evidence={"token_text": "secret"})

    with pytest.raises(
        ValueError, match="lab payload contains forbidden field: token_text"
    ):
        store.put(unsafe)

    assert store.snapshot() == ()


def test_store_evicts_the_oldest_completed_run_at_capacity() -> None:
    clock = FakeClock()
    store = LabRunStore(capacity=2, ttl_seconds=15, clock=clock)
    store.put(StoredRun(run_id="lab_1"))
    clock.advance(1)
    store.put(StoredRun(run_id="lab_2"))
    clock.advance(1)

    store.put(StoredRun(run_id="lab_3"))

    with pytest.raises(LabRunNotFound):
        store.get("lab_1")
    assert [run.run_id for run in store.snapshot()] == ["lab_2", "lab_3"]


def test_store_reports_a_known_run_as_expired_at_the_ttl_boundary() -> None:
    clock = FakeClock()
    store = LabRunStore(capacity=2, ttl_seconds=15, clock=clock)
    store.put(StoredRun(run_id="lab_1"))
    clock.advance(15)

    with pytest.raises(LabRunExpired, match="lab_1"):
        store.get("lab_1")
    assert store.snapshot() == ()


def test_store_distinguishes_unknown_ids_from_expired_ids() -> None:
    store = LabRunStore(capacity=2, ttl_seconds=15, clock=FakeClock())

    with pytest.raises(LabRunNotFound, match="unknown"):
        store.get("unknown")


def test_store_put_replaces_a_run_without_growing_capacity() -> None:
    store = LabRunStore(capacity=2, ttl_seconds=15, clock=FakeClock())
    store.put(StoredRun(run_id="lab_1", evidence={"decision": "review"}))

    replacement = StoredRun(run_id="lab_1", evidence={"decision": "block"})
    store.put(replacement)

    assert store.snapshot() == (replacement,)


def test_store_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError, match="capacity must be positive"):
        LabRunStore(capacity=0)
    with pytest.raises(ValueError, match="ttl_seconds must be positive"):
        LabRunStore(ttl_seconds=0)


def test_store_is_safe_under_concurrent_puts_and_gets() -> None:
    store = LabRunStore(capacity=32, ttl_seconds=900, clock=FakeClock())

    def write(index: int) -> None:
        run = StoredRun(run_id=f"lab_{index}", evidence={"index": index})
        store.put(run)
        try:
            store.get(run.run_id)
        except LabRunNotFound:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write, range(96)))

    snapshot = store.snapshot()
    assert len(snapshot) == 32
    assert len({run.run_id for run in snapshot}) == 32
