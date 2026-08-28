from __future__ import annotations

import pytest

from app.schemas import Decision
from app.superagent.models import (
    SuperAgentFinalStatus,
    SuperAgentMissionResult,
    SuperAgentObjective,
)
from app.superagent.store import (
    SuperAgentMissionExpired,
    SuperAgentMissionNotFound,
    SuperAgentMissionStore,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 50.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _mission(index: int) -> SuperAgentMissionResult:
    return SuperAgentMissionResult(
        mission_id=f"mission_{index:032x}",
        run_id=f"lab_{index:032x}",
        objective=SuperAgentObjective.INVESTIGATE_AND_RESPOND,
        scenario_id="synthetic_safe",
        scenario_label="普通无害",
        mode="analysis",
        base_action=Decision.ALLOW,
        final_status=SuperAgentFinalStatus.CLOSED_SAFE,
        initial_plan=(),
        final_plan=(),
        events=(),
        executions=(),
        limitations=("仅执行平台内部仿真工具。",),
        created_at="2026-08-29T02:00:00Z",
    )


def test_store_restores_a_public_mission_and_evicts_oldest() -> None:
    clock = FakeClock()
    store = SuperAgentMissionStore(capacity=2, ttl_seconds=10, clock=clock)
    store.put(_mission(1))
    clock.advance(1)
    store.put(_mission(2))
    clock.advance(1)
    store.put(_mission(3))

    with pytest.raises(SuperAgentMissionNotFound):
        store.get("mission_00000000000000000000000000000001")
    assert [item.mission_id for item in store.snapshot()] == [
        "mission_00000000000000000000000000000002",
        "mission_00000000000000000000000000000003",
    ]


def test_store_distinguishes_expired_and_unknown_missions() -> None:
    clock = FakeClock()
    store = SuperAgentMissionStore(capacity=2, ttl_seconds=10, clock=clock)
    store.put(_mission(1))
    clock.advance(10)

    with pytest.raises(SuperAgentMissionExpired):
        store.get("mission_00000000000000000000000000000001")
    with pytest.raises(SuperAgentMissionNotFound):
        store.get("mission_ffffffffffffffffffffffffffffffff")


def test_store_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError, match="capacity must be positive"):
        SuperAgentMissionStore(capacity=0)
    with pytest.raises(ValueError, match="ttl_seconds must be positive"):
        SuperAgentMissionStore(ttl_seconds=0)
