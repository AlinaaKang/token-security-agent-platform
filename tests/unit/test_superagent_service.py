from __future__ import annotations

from datetime import UTC, datetime
from threading import Event
from types import SimpleNamespace
from uuid import UUID

import pytest

from app.lab.execution_models import (
    LabExecuteRequest,
    LabExecutionStatus,
    LabToolExecution,
)
from app.lab.models import LabToolId, assert_public_payload
from app.lab.service import LabToolStorageUnavailable
from app.pcap.authorization import PcapAuthorizationStore
from app.pcap.models import PcapBatchSummary, PcapMissionResult
from app.schemas import Decision
from app.superagent.models import (
    PcapTriageMissionRequest,
    SuperAgentFinalStatus,
    SuperAgentMissionRequest,
    SuperAgentTracePhase,
)
from app.superagent.pcap_coordinator import PcapMissionCoordinator
from app.superagent.service import SuperAgentService
from app.superagent.store import SuperAgentMissionStore


class FakeLabService:
    def __init__(
        self,
        *,
        decision: Decision,
        fail_tool: LabToolId | None = None,
    ) -> None:
        self.decision = decision
        self.fail_tool = fail_tool
        self.requests: list[object] = []
        self.executed: list[tuple[LabToolId, UUID]] = []

    def create_run(self, request: object) -> SimpleNamespace:
        self.requests.append(request)
        return _run(self.decision)

    def execute_tool(
        self,
        run_id: str,
        tool_id: LabToolId,
        request: LabExecuteRequest,
    ) -> tuple[LabToolExecution, bool]:
        assert run_id == "lab_0123456789abcdef0123456789abcdef"
        self.executed.append((tool_id, request.idempotency_key))
        if tool_id is self.fail_tool:
            raise LabToolStorageUnavailable("private details must not escape")
        return (
            LabToolExecution(
                execution_id=f"exec_{len(self.executed):032x}",
                run_id=run_id,
                tool_id=tool_id,
                idempotency_key=request.idempotency_key,
                status=LabExecutionStatus.SUCCEEDED,
                source_action=self.decision,
                effective_action=self.decision,
                model_provenance_sha256="sha256:" + "1" * 64,
                calibration_provenance_sha256="sha256:" + "2" * 64,
                knowledge_snapshot_sha256="sha256:" + "3" * 64,
                knowledge_ids=("owasp-llm01-prompt-injection",),
                receipt_id=f"receipt_{len(self.executed):032x}",
                artifact_id=(
                    f"artifact_{len(self.executed):032x}"
                    if tool_id is LabToolId.EVIDENCE_BUNDLE
                    else None
                ),
                evidence_sha256=(
                    "sha256:" + "4" * 64
                    if tool_id is LabToolId.EVIDENCE_BUNDLE
                    else None
                ),
                latency_ms=2.5,
                created_at=datetime(2026, 8, 29, 2, 0, tzinfo=UTC),
            ),
            True,
        )


class FakePcapCoordinator:
    def __init__(self) -> None:
        self.started = 0

    def start(self, request: PcapTriageMissionRequest) -> PcapMissionResult:
        self.started += 1
        return PcapMissionResult(
            mission_id="mission_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            status="queued",
            batch_id="batch_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            events=(),
            report={},
            limitations=("no_packet_payload_retained",),
            created_at="2026-09-01T00:00:00Z",
        )


class BlockingPcapExecutor:
    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()

    def execute(self, batch_id: str, max_files: int) -> PcapBatchSummary:
        self.started.set()
        assert self.release.wait(timeout=3)
        return PcapBatchSummary(
            batch_id=batch_id,
            selected_count=0,
            succeeded_count=0,
            failed_count=0,
            skipped_count=0,
            captures=(),
        )

    def request_cancel(self, batch_id: str) -> None:
        self.release.set()


def _run(decision: Decision) -> SimpleNamespace:
    severity = "safe" if decision is Decision.ALLOW else "unsafe"
    detector_status = (
        "no_token_anomaly"
        if decision is Decision.ALLOW
        else "token_anomaly_candidate"
    )
    return SimpleNamespace(
        run_id="lab_0123456789abcdef0123456789abcdef",
        scenario_id="synthetic_safe" if decision is Decision.ALLOW else "sample_01",
        scenario_label="普通无害" if decision is Decision.ALLOW else "GCG 优化攻击",
        attack_family=None if decision is Decision.ALLOW else "gcg",
        mode="analysis",
        created_at="2026-08-29T02:00:00Z",
        detection=SimpleNamespace(
            decision=decision,
            semantic_severity=severity,
            semantic_categories=() if decision is Decision.ALLOW else ("jailbreak",),
            detector_status=detector_status,
            suspicious_span=(
                None
                if decision is Decision.ALLOW
                else {"token_start": 42, "char_start": 120}
            ),
            knowledge_status="ready",
            knowledge_evidence=(
                SimpleNamespace(
                    knowledge_id="owasp-llm01-prompt-injection"
                ),
            ),
            fusion_reason=(
                "both_clear" if decision is Decision.ALLOW else "semantic_unsafe"
            ),
        ),
        counterfactual=SimpleNamespace(
            interpretation=(
                "unchanged" if decision is Decision.ALLOW else "risk_reduced"
            ),
            reason=(
                "no_predicted_onset" if decision is Decision.ALLOW else "completed"
            ),
        ),
    )


def _request() -> SuperAgentMissionRequest:
    return SuperAgentMissionRequest(
        objective="investigate_and_respond",
        scenario_kind="frozen",
        sample_id="synthetic_safe",
        mode="analysis",
    )


def test_allow_mission_closes_without_tools() -> None:
    lab = FakeLabService(decision=Decision.ALLOW)
    service = SuperAgentService(lab_service=lab)

    result = service.create_mission(_request())

    assert result.final_status is SuperAgentFinalStatus.CLOSED_SAFE
    assert result.final_plan == ()
    assert result.executions == ()
    assert lab.executed == []
    assert {event.phase for event in result.events} == set(SuperAgentTracePhase)
    assert len(result.events) <= 12
    assert service.get_mission(result.mission_id) == result
    assert_public_payload(result)


def test_pcap_objective_delegates_only_to_pcap_coordinator() -> None:
    lab = FakeLabService(decision=Decision.BLOCK)
    pcap = FakePcapCoordinator()
    service = SuperAgentService(lab_service=lab, pcap_coordinator=pcap)

    result = service.create_mission(
        PcapTriageMissionRequest(
            objective="triage_pcap_evidence",
            authorization_id="pcap_auth_" + "a" * 32,
        )
    )

    assert result.objective == "triage_pcap_evidence"
    assert pcap.started == 1
    assert lab.requests == []
    assert lab.executed == []


def test_existing_prompt_objective_never_calls_pcap_coordinator() -> None:
    pcap = FakePcapCoordinator()
    service = SuperAgentService(
        lab_service=FakeLabService(decision=Decision.ALLOW),
        pcap_coordinator=pcap,
    )

    result = service.create_mission(_request())

    assert result.final_status is SuperAgentFinalStatus.CLOSED_SAFE
    assert pcap.started == 0


def test_prompt_mission_remains_stored_and_executes_under_pcap_load() -> None:
    store = SuperAgentMissionStore(capacity=2)
    authorizations = PcapAuthorizationStore()
    executor = BlockingPcapExecutor()
    coordinator = PcapMissionCoordinator(
        authorization_store=authorizations,
        executor=executor,
        mission_store=store,
    )
    lab = FakeLabService(decision=Decision.BLOCK)
    service = SuperAgentService(
        lab_service=lab,
        mission_store=store,
        pcap_coordinator=coordinator,
    )
    receipt = authorizations.issue(max_files=1)
    try:
        pcap = service.create_mission(
            PcapTriageMissionRequest(
                objective="triage_pcap_evidence",
                authorization_id=receipt.authorization_id,
            )
        )
        assert executor.started.wait(timeout=3)
        prompt = service.create_mission(_request())
    finally:
        executor.release.set()
        coordinator.close()

    assert service.get_mission(pcap.mission_id).mission_id == pcap.mission_id
    assert service.get_mission(prompt.mission_id) == prompt
    assert prompt.final_status is SuperAgentFinalStatus.CONTAINED
    assert len(lab.executed) == 3


def test_block_mission_executes_each_internal_tool_once_in_policy_order() -> None:
    lab = FakeLabService(decision=Decision.BLOCK)
    service = SuperAgentService(lab_service=lab)

    result = service.create_mission(_request())

    expected = (
        LabToolId.GATEWAY_ENFORCEMENT,
        LabToolId.SECURITY_CASE,
        LabToolId.EVIDENCE_BUNDLE,
    )
    assert result.final_plan == expected
    assert tuple(item.tool_id for item in result.executions) == expected
    assert tuple(tool_id for tool_id, _ in lab.executed) == expected
    assert len({key for _, key in lab.executed}) == 3
    assert all(item.source_action is Decision.BLOCK for item in result.executions)
    assert all(item.effective_action is Decision.BLOCK for item in result.executions)
    assert result.final_status is SuperAgentFinalStatus.CONTAINED
    assert len(result.events) == 12


@pytest.mark.parametrize("decision", [Decision.REVIEW, Decision.SANITIZE_RECHECK])
def test_review_like_mission_never_executes_gateway_enforcement(
    decision: Decision,
) -> None:
    lab = FakeLabService(decision=decision)
    service = SuperAgentService(lab_service=lab)

    result = service.create_mission(_request())

    assert result.final_plan == (
        LabToolId.SECURITY_CASE,
        LabToolId.EVIDENCE_BUNDLE,
    )
    assert LabToolId.GATEWAY_ENFORCEMENT not in {
        tool_id for tool_id, _ in lab.executed
    }
    assert result.final_status is SuperAgentFinalStatus.REVIEW_REQUIRED


def test_tool_storage_failure_keeps_base_action_and_degrades_without_retry() -> None:
    lab = FakeLabService(
        decision=Decision.BLOCK,
        fail_tool=LabToolId.GATEWAY_ENFORCEMENT,
    )
    service = SuperAgentService(lab_service=lab)

    result = service.create_mission(_request())

    assert result.final_status is SuperAgentFinalStatus.DEGRADED
    assert [tool_id for tool_id, _ in lab.executed].count(
        LabToolId.GATEWAY_ENFORCEMENT
    ) == 1
    failed = result.executions[0]
    assert failed.status == "failed"
    assert failed.source_action is Decision.BLOCK
    assert failed.effective_action is Decision.BLOCK
    assert "private details" not in str(result.model_dump(mode="json"))
