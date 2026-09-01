from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from app.lab.models import LabToolId, assert_public_payload
from app.schemas import Decision
from app.superagent.models import (
    PcapTriageMissionRequest,
    SuperAgentActor,
    SuperAgentCreateMissionRequest,
    SuperAgentFinalStatus,
    SuperAgentMissionRequest,
    SuperAgentMissionResult,
    SuperAgentObjective,
    SuperAgentPlanStep,
    SuperAgentTraceEvent,
    SuperAgentTracePhase,
)


def _mission() -> SuperAgentMissionResult:
    return SuperAgentMissionResult(
        mission_id="mission_0123456789abcdef0123456789abcdef",
        run_id="lab_0123456789abcdef0123456789abcdef",
        objective=SuperAgentObjective.INVESTIGATE_AND_RESPOND,
        scenario_id="synthetic_safe",
        scenario_label="普通无害",
        mode="analysis",
        base_action=Decision.ALLOW,
        final_status=SuperAgentFinalStatus.CLOSED_SAFE,
        initial_plan=(
            SuperAgentPlanStep(
                sequence=1,
                actor=SuperAgentActor.COORDINATOR,
                action_code="collect_bounded_evidence",
                summary="收集平台内部结构化证据。",
            ),
        ),
        final_plan=(),
        events=(
            SuperAgentTraceEvent(
                sequence=1,
                phase=SuperAgentTracePhase.PLAN,
                actor=SuperAgentActor.COORDINATOR,
                status="succeeded",
                summary="已建立有界调查计划。",
                evidence_codes=("policy:bounded-react-v1",),
            ),
        ),
        executions=(),
        limitations=("仅执行平台内部仿真工具。",),
        created_at="2026-08-29T02:00:00Z",
    )


def test_mission_request_accepts_only_the_fixed_objective_and_frozen_source() -> None:
    request = SuperAgentMissionRequest(
        objective="investigate_and_respond",
        scenario_kind="frozen",
        sample_id="synthetic_safe",
        mode="analysis",
    )

    assert request.objective is SuperAgentObjective.INVESTIGATE_AND_RESPOND
    assert request.sample_id == "synthetic_safe"

    with pytest.raises(ValidationError):
        SuperAgentMissionRequest.model_validate(
            {
                **request.model_dump(mode="json"),
                "command": "inspect everything",
            }
        )
    with pytest.raises(ValidationError):
        SuperAgentMissionRequest(
            objective="free_form",
            scenario_kind="frozen",
            sample_id="synthetic_safe",
        )
    with pytest.raises(ValidationError):
        SuperAgentMissionRequest(
            objective="investigate_and_respond",
            scenario_kind="custom",
            sample_id="synthetic_safe",
        )


def test_create_mission_request_discriminates_prompt_and_pcap_objectives() -> None:
    adapter = TypeAdapter(SuperAgentCreateMissionRequest)

    prompt = adapter.validate_python(
        {
            "objective": "investigate_and_respond",
            "scenario_kind": "frozen",
            "sample_id": "synthetic_safe",
            "mode": "analysis",
        }
    )
    pcap = adapter.validate_python(
        {
            "objective": "triage_pcap_evidence",
            "authorization_id": "pcap_auth_" + "a" * 32,
        }
    )

    assert isinstance(prompt, SuperAgentMissionRequest)
    assert isinstance(pcap, PcapTriageMissionRequest)
    assert prompt.model_dump(mode="json") == {
        "objective": "investigate_and_respond",
        "scenario_kind": "frozen",
        "sample_id": "synthetic_safe",
        "mode": "analysis",
    }
    assert pcap.model_dump(mode="json") == {
        "objective": "triage_pcap_evidence",
        "authorization_id": "pcap_auth_" + "a" * 32,
    }


def test_pcap_mission_request_rejects_prompt_fields_and_malformed_authorization() -> None:
    with pytest.raises(ValidationError):
        PcapTriageMissionRequest.model_validate(
            {
                "objective": "triage_pcap_evidence",
                "authorization_id": "pcap_auth_" + "a" * 32,
                "sample_id": "synthetic_safe",
            }
        )
    with pytest.raises(ValidationError):
        PcapTriageMissionRequest(
            objective="triage_pcap_evidence",
            authorization_id="pcap_auth_" + "A" * 32,
        )


def test_mission_result_is_immutable_and_public() -> None:
    mission = _mission()

    assert_public_payload(mission)
    with pytest.raises(ValidationError):
        mission.final_status = SuperAgentFinalStatus.DEGRADED


def test_mission_models_reject_hidden_reasoning_and_unbounded_sequences() -> None:
    with pytest.raises(ValidationError):
        SuperAgentTraceEvent(
            sequence=13,
            phase="observe",
            actor="coordinator",
            status="succeeded",
            summary="越界事件。",
        )
    with pytest.raises(ValidationError):
        SuperAgentPlanStep.model_validate(
            {
                "sequence": 1,
                "actor": "coordinator",
                "action_code": "unsafe",
                "summary": "不安全字段。",
                "hidden_reasoning": "private",
            }
        )


def test_execution_reference_requires_monotonic_action() -> None:
    from app.superagent.models import SuperAgentExecutionReference

    with pytest.raises(ValidationError, match="cannot be weaker"):
        SuperAgentExecutionReference(
            execution_id="exec_0123456789abcdef0123456789abcdef",
            tool_id=LabToolId.GATEWAY_ENFORCEMENT,
            status="succeeded",
            source_action=Decision.BLOCK,
            effective_action=Decision.ALLOW,
        )
