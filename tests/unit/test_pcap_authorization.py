from __future__ import annotations

from dataclasses import asdict
import math
import re
from threading import Barrier, Thread

import pytest

from app.pcap.authorization import (
    PcapAuthorizationAlreadyUsed,
    PcapAuthorizationExpired,
    PcapAuthorizationStore,
    PcapAuthorizationUnknown,
)


class MutableClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_authorization_is_single_use_bound_and_expiring() -> None:
    clock = MutableClock()
    store = PcapAuthorizationStore(ttl_seconds=30, clock=clock)

    receipt = store.issue(max_files=20)
    consumed = store.consume(receipt.authorization_id)

    assert consumed.max_files == 20
    assert consumed.authorization_id == receipt.authorization_id
    with pytest.raises(PcapAuthorizationAlreadyUsed):
        store.consume(receipt.authorization_id)

    expired = store.issue(max_files=3)
    clock.advance(31)

    with pytest.raises(PcapAuthorizationExpired):
        store.consume(expired.authorization_id)


@pytest.mark.parametrize("max_files", [0, 21, True, 1.5])
def test_authorization_rejects_max_files_outside_the_bounded_integer_range(
    max_files: object,
) -> None:
    store = PcapAuthorizationStore()

    with pytest.raises(ValueError, match="max_files"):
        store.issue(max_files=max_files)  # type: ignore[arg-type]


def test_authorization_rejects_an_unknown_opaque_id() -> None:
    with pytest.raises(PcapAuthorizationUnknown):
        PcapAuthorizationStore().consume("pcap_auth_" + "a" * 32)


@pytest.mark.parametrize("ttl_seconds", [math.nan, math.inf, -math.inf])
def test_authorization_rejects_non_finite_ttls(ttl_seconds: float) -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        PcapAuthorizationStore(ttl_seconds=ttl_seconds)


def test_authorization_allows_exactly_one_concurrent_consumer() -> None:
    store = PcapAuthorizationStore()
    receipt = store.issue(max_files=1)
    barrier = Barrier(8)
    consumed: list[object] = []
    failures: list[BaseException] = []

    def consume() -> None:
        barrier.wait()
        try:
            consumed.append(store.consume(receipt.authorization_id))
        except BaseException as error:
            failures.append(error)

    workers = [Thread(target=consume) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert len(consumed) == 1
    assert len(failures) == 7
    assert all(isinstance(error, PcapAuthorizationAlreadyUsed) for error in failures)


def test_authorization_store_evicts_oldest_entry_at_its_bounded_capacity() -> None:
    store = PcapAuthorizationStore(capacity=1)
    first = store.issue(max_files=1)
    store.issue(max_files=2)

    with pytest.raises(PcapAuthorizationUnknown):
        store.consume(first.authorization_id)


def test_authorization_receipt_is_opaque_and_contains_no_location_data() -> None:
    receipt = PcapAuthorizationStore(ttl_seconds=10).issue(max_files=1)
    payload = asdict(receipt)

    assert re.fullmatch(r"pcap_auth_[0-9a-f]{32}", receipt.authorization_id)
    assert payload["max_files"] == 1
    assert not {"root", "path", "quarantine_root", "batch_script"}.intersection(payload)
