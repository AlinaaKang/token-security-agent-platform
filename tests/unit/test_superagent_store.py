from __future__ import annotations

import pytest

from app.pcap.models import PcapMissionResult, PcapMissionStatus
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


def _pcap_mission(index: int) -> PcapMissionResult:
    return PcapMissionResult(
        mission_id=f"mission_{index:032x}",
        status="queued",
        batch_id=f"batch_{index:032x}",
        events=(),
        report={},
        limitations=("no_packet_payload_retained",),
        created_at="2026-09-01T00:00:00Z",
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


@pytest.mark.parametrize(
    "status",
    [PcapMissionStatus.QUEUED, PcapMissionStatus.RUNNING],
)
def test_store_does_not_expire_active_pcap_missions(
    status: PcapMissionStatus,
) -> None:
    clock = FakeClock()
    store = SuperAgentMissionStore(capacity=2, ttl_seconds=10, clock=clock)
    active = _pcap_mission(1).model_copy(update={"status": status})
    store.put(active)
    clock.advance(11)

    assert store.get(active.mission_id) is active

    terminal = active.model_copy(update={"status": PcapMissionStatus.COMPLETED})
    store.put(terminal)
    clock.advance(10)
    with pytest.raises(SuperAgentMissionExpired):
        store.get(active.mission_id)


def test_store_restores_prompt_and_pcap_missions_without_contract_mixing() -> None:
    store = SuperAgentMissionStore()
    prompt = _mission(1)
    pcap = _pcap_mission(2)

    store.put(prompt)
    store.put(pcap)

    assert store.get(prompt.mission_id) is prompt
    assert store.get(pcap.mission_id) is pcap
    assert [item.objective for item in store.snapshot()] == [
        "investigate_and_respond",
        "triage_pcap_evidence",
    ]


def test_store_preserves_active_pcap_missions_at_capacity() -> None:
    store = SuperAgentMissionStore(capacity=1)
    active = _pcap_mission(1)
    store.put(active)

    with pytest.raises(ValueError, match="active PCAP missions"):
        store.put(_mission(2))
    assert store.get(active.mission_id) is active

    with pytest.raises(ValueError, match="active PCAP missions"):
        store.put(_pcap_mission(3))
    assert store.get(active.mission_id) is active


def test_store_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError, match="capacity must be positive"):
        SuperAgentMissionStore(capacity=0)
    with pytest.raises(ValueError, match="ttl_seconds must be positive"):
        SuperAgentMissionStore(ttl_seconds=0)
