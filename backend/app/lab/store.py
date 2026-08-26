from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable
from threading import RLock
from typing import Generic, TypeVar

from pydantic import BaseModel

from app.lab.models import assert_public_payload


RunT = TypeVar("RunT", bound=BaseModel)


class LabRunNotFound(LookupError):
    pass


class LabRunExpired(LookupError):
    pass


class LabRunStore(Generic[RunT]):
    def __init__(
        self,
        *,
        capacity: int = 32,
        ttl_seconds: float = 900,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._runs: OrderedDict[str, tuple[float, RunT]] = OrderedDict()
        self._expired_order: deque[str] = deque(maxlen=capacity * 4)
        self._expired_ids: set[str] = set()
        self._lock = RLock()

    def put(self, run: RunT) -> None:
        assert_public_payload(run)
        run_id = _run_id(run)
        with self._lock:
            self._purge_expired(self._clock())
            self._runs.pop(run_id, None)
            self._forget_expired(run_id)
            self._runs[run_id] = (self._clock(), run)
            while len(self._runs) > self.capacity:
                self._runs.popitem(last=False)

    def get(self, run_id: str) -> RunT:
        with self._lock:
            self._purge_expired(self._clock())
            stored = self._runs.get(run_id)
            if stored is not None:
                return stored[1]
            if run_id in self._expired_ids:
                raise LabRunExpired(run_id)
            raise LabRunNotFound(run_id)

    def snapshot(self) -> tuple[RunT, ...]:
        with self._lock:
            self._purge_expired(self._clock())
            return tuple(run for _, run in self._runs.values())

    def _purge_expired(self, now: float) -> None:
        expired = [
            run_id
            for run_id, (completed_at, _) in self._runs.items()
            if now - completed_at >= self.ttl_seconds
        ]
        for run_id in expired:
            self._runs.pop(run_id, None)
            self._remember_expired(run_id)

    def _remember_expired(self, run_id: str) -> None:
        if len(self._expired_order) == self._expired_order.maxlen:
            oldest = self._expired_order.popleft()
            self._expired_ids.discard(oldest)
        self._expired_order.append(run_id)
        self._expired_ids.add(run_id)

    def _forget_expired(self, run_id: str) -> None:
        if run_id not in self._expired_ids:
            return
        self._expired_ids.discard(run_id)
        self._expired_order = deque(
            (value for value in self._expired_order if value != run_id),
            maxlen=self.capacity * 4,
        )


def _run_id(run: BaseModel) -> str:
    value = getattr(run, "run_id", None)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("stored lab run must have a non-empty run_id")
    return value
