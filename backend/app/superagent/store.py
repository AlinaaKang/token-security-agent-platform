from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable
from threading import RLock

from app.lab.models import assert_public_payload
from app.pcap.models import PcapMissionResult, PcapMissionStatus
from app.pcap.recon_models import PcapReconMissionResult
from app.superagent.models import SuperAgentStoredMission


class SuperAgentMissionNotFound(LookupError):
    pass


class SuperAgentMissionExpired(LookupError):
    pass


class SuperAgentMissionStore:
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
        self._missions: OrderedDict[
            str, tuple[float, SuperAgentStoredMission]
        ] = OrderedDict()
        self._expired_order: deque[str] = deque(maxlen=capacity * 4)
        self._expired_ids: set[str] = set()
        self._lock = RLock()

    def put(self, mission: SuperAgentStoredMission) -> None:
        assert_public_payload(mission)
        with self._lock:
            now = self._clock()
            self._purge_expired(now)
            mission_id = _mission_id(mission)
            self._missions.pop(mission_id, None)
            self._forget_expired(mission_id)
            self._missions[mission_id] = (now, mission)
            while len(self._missions) > self.capacity:
                eviction_id = next(
                    (
                        mission_id
                        for mission_id, (_, candidate) in self._missions.items()
                        if not _is_active_pcap_mission(candidate)
                    ),
                    None,
                )
                if eviction_id is None or eviction_id == mission_id:
                    self._missions.pop(mission_id, None)
                    raise ValueError(
                        "mission store capacity is occupied by active PCAP missions"
                    )
                self._missions.pop(eviction_id)

    def get(self, mission_id: str) -> SuperAgentStoredMission:
        with self._lock:
            self._purge_expired(self._clock())
            stored = self._missions.get(mission_id)
            if stored is not None:
                return stored[1]
            if mission_id in self._expired_ids:
                raise SuperAgentMissionExpired(mission_id)
            raise SuperAgentMissionNotFound(mission_id)

    def snapshot(self) -> tuple[SuperAgentStoredMission, ...]:
        with self._lock:
            self._purge_expired(self._clock())
            return tuple(item for _, item in self._missions.values())

    def _purge_expired(self, now: float) -> None:
        expired = [
            mission_id
            for mission_id, (completed_at, mission) in self._missions.items()
            if now - completed_at >= self.ttl_seconds
            and not _is_active_pcap_mission(mission)
        ]
        for mission_id in expired:
            self._missions.pop(mission_id, None)
            self._remember_expired(mission_id)

    def _remember_expired(self, mission_id: str) -> None:
        if len(self._expired_order) == self._expired_order.maxlen:
            oldest = self._expired_order.popleft()
            self._expired_ids.discard(oldest)
        self._expired_order.append(mission_id)
        self._expired_ids.add(mission_id)

    def _forget_expired(self, mission_id: str) -> None:
        if mission_id not in self._expired_ids:
            return
        self._expired_ids.discard(mission_id)
        self._expired_order = deque(
            (value for value in self._expired_order if value != mission_id),
            maxlen=self.capacity * 4,
        )


def _is_active_pcap_mission(mission: SuperAgentStoredMission) -> bool:
    return isinstance(mission, (PcapMissionResult, PcapReconMissionResult)) and mission.status in {
        PcapMissionStatus.QUEUED,
        PcapMissionStatus.RUNNING,
    }


def _mission_id(mission: SuperAgentStoredMission) -> str:
    mission_id = getattr(mission, "mission_id", None)
    return mission_id if mission_id is not None else mission.recon_id
