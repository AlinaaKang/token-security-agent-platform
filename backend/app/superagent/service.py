from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from app.lab.execution_models import LabExecuteRequest, LabToolExecution
from app.lab.models import LabRunRequest, LabToolId, assert_public_payload
from app.lab.service import (
    LabExecutionInvariantViolation,
    LabToolStorageUnavailable,
)
from app.pcap.models import PcapMissionResult
from app.pcap.detection_models import PcapDetectionMissionResult
from app.pcap.recon_models import PcapReconMissionResult
from app.superagent.models import (
    PcapReconMissionRequest,
    PcapDetectionMissionRequest,
    PcapTriageMissionRequest,
    SuperAgentActor,
    SuperAgentCapabilities,
    SuperAgentCreateMissionRequest,
    SuperAgentExecutionReference,
    SuperAgentMissionRequest,
    SuperAgentMissionResult,
    SuperAgentPlanStep,
    SuperAgentTraceEvent,
    SuperAgentTracePhase,
    SuperAgentStoredMission,
)
from app.superagent.policy import final_status_for, response_tools_for
from app.superagent.store import SuperAgentMissionStore


_LIMITATIONS = (
    "仅执行平台内部仿真工具，不代表已联动外部安全设备。",
    "轨迹是结构化审计事件，不包含模型隐藏思维链。",
)


class SuperAgentMissionFailed(RuntimeError):
    pass


class SuperAgentService:
    def __init__(
        self,
        *,
        lab_service: Any,
        mission_store: SuperAgentMissionStore | None = None,
        pcap_coordinator: Any | None = None,
        pcap_recon_coordinator: Any | None = None,
        pcap_detection_coordinator: Any | None = None,
    ) -> None:
        self.lab_service = lab_service
        self.pcap_coordinator = pcap_coordinator
        self.pcap_recon_coordinator = pcap_recon_coordinator
        self.pcap_detection_coordinator = pcap_detection_coordinator
        coordinator_store = getattr(pcap_coordinator, "mission_store", None)
        recon_store = getattr(pcap_recon_coordinator, "mission_store", None)
        detection_store = getattr(pcap_detection_coordinator, "mission_store", None)
        stores = tuple(
            store
            for store in (coordinator_store, recon_store, detection_store)
            if store is not None
        )
        if stores and any(store is not stores[0] for store in stores[1:]):
            raise ValueError("pcap coordinator must use the common mission store")
        if mission_store is not None and any(
            store is not None and store is not mission_store
            for store in stores
        ):
            raise ValueError("pcap coordinator must use the common mission store")
        self.mission_store = (
            mission_store
            if mission_store is not None
            else coordinator_store
            or recon_store
            or detection_store
            or SuperAgentMissionStore()
        )

    def capabilities(self) -> SuperAgentCapabilities:
        return SuperAgentCapabilities()

    def get_mission(self, mission_id: str) -> SuperAgentStoredMission:
        return self.mission_store.get(mission_id)

    def create_mission(
        self, request: SuperAgentCreateMissionRequest
    ) -> (
        SuperAgentMissionResult
        | PcapMissionResult
        | PcapReconMissionResult
        | PcapDetectionMissionResult
    ):
        if isinstance(request, PcapTriageMissionRequest):
            if self.pcap_coordinator is None:
                raise SuperAgentMissionFailed("pcap_triage_unavailable")
            return self.pcap_coordinator.start(request)
        if isinstance(request, PcapReconMissionRequest):
            if self.pcap_recon_coordinator is None:
                raise SuperAgentMissionFailed("pcap_reconnaissance_unavailable")
            return self.pcap_recon_coordinator.start(request)
        if isinstance(request, PcapDetectionMissionRequest):
            if self.pcap_detection_coordinator is None:
                raise SuperAgentMissionFailed("pcap_detection_unavailable")
            return self.pcap_detection_coordinator.start(request)
        try:
            return self._create_mission(request)
        except SuperAgentMissionFailed:
            raise
        except Exception:
            raise SuperAgentMissionFailed("superagent_mission_failed") from None

    def _create_mission(
        self, request: SuperAgentMissionRequest
    ) -> SuperAgentMissionResult:
        mission_id = f"mission_{uuid.uuid4().hex}"
        initial_plan = _initial_plan()
        events: list[SuperAgentTraceEvent] = []

        _append_event(
            events,
            phase=SuperAgentTracePhase.PLAN,
            actor=SuperAgentActor.COORDINATOR,
            status="succeeded",
            summary="已建立有界调查计划，等待结构化证据。",
            evidence_codes=("policy:bounded-react-v1",),
        )
        run = self.lab_service.create_run(
            LabRunRequest(
                scenario_kind="frozen",
                sample_id=request.sample_id,
                mode=request.mode,
            )
        )
        _append_event(
            events,
            phase=SuperAgentTracePhase.ACT,
            actor=SuperAgentActor.COORDINATOR,
            status="succeeded",
            summary="基础检测与反事实检查已经完成。",
            evidence_codes=("source:lab-run",),
        )
        _append_detection_observations(events, run)

        final_plan = response_tools_for(run.detection.decision)
        plan_code = (
            "response:none"
            if not final_plan
            else "response:" + ",".join(tool.value for tool in final_plan)
        )
        _append_event(
            events,
            phase=SuperAgentTracePhase.REPLAN,
            actor=SuperAgentActor.COORDINATOR,
            status="succeeded",
            summary=_replan_summary(run.detection.decision, final_plan),
            evidence_codes=(
                f"base_action:{run.detection.decision.value}",
                plan_code,
            ),
        )

        executions: list[SuperAgentExecutionReference] = []
        for tool_id in final_plan:
            idempotency_key = _tool_idempotency_key(mission_id, tool_id)
            try:
                execution, _ = self.lab_service.execute_tool(
                    run.run_id,
                    tool_id,
                    LabExecuteRequest(
                        confirmed=True,
                        idempotency_key=idempotency_key,
                    ),
                )
                reference = _execution_reference(execution)
            except (LabToolStorageUnavailable, LabExecutionInvariantViolation):
                reference = SuperAgentExecutionReference(
                    execution_id=f"failed_{idempotency_key.hex}",
                    tool_id=tool_id,
                    status="failed",
                    source_action=run.detection.decision,
                    effective_action=run.detection.decision,
                )
            executions.append(reference)
            _append_event(
                events,
                phase=SuperAgentTracePhase.ACT,
                actor=SuperAgentActor.RESPONSE_OPERATOR,
                status=reference.status,
                summary=_tool_summary(tool_id, reference.status),
                evidence_codes=(
                    f"tool:{tool_id.value}",
                    f"action:{reference.effective_action.value}",
                ),
                tool_id=tool_id,
            )

        all_succeeded = all(item.status == "succeeded" for item in executions)
        _append_event(
            events,
            phase=SuperAgentTracePhase.OBSERVE,
            actor=SuperAgentActor.RESPONSE_OPERATOR,
            status=("succeeded" if all_succeeded else "failed"),
            summary=(
                "内部工具回执已核验，执行动作保持基础判定。"
                if executions and all_succeeded
                else (
                    "无需执行处置工具，基础判定保持放行。"
                    if not executions
                    else "内部工具存在失败，基础动作保持不变并进入降级收口。"
                )
            ),
            evidence_codes=(
                f"execution_count:{len(executions)}",
                f"base_action:{run.detection.decision.value}",
            ),
        )
        final_status = final_status_for(
            run.detection.decision, final_plan, executions
        )
        _append_event(
            events,
            phase=SuperAgentTracePhase.COMPLETE,
            actor=SuperAgentActor.COORDINATOR,
            status=(
                "failed" if final_status.value == "degraded" else "succeeded"
            ),
            summary=_completion_summary(final_status.value),
            evidence_codes=(f"final_status:{final_status.value}",),
        )

        mission = SuperAgentMissionResult(
            mission_id=mission_id,
            run_id=run.run_id,
            objective=request.objective,
            scenario_id=run.scenario_id,
            scenario_label=run.scenario_label,
            attack_family=run.attack_family,
            mode=run.mode,
            base_action=run.detection.decision,
            final_status=final_status,
            initial_plan=initial_plan,
            final_plan=final_plan,
            events=tuple(events),
            executions=tuple(executions),
            limitations=_LIMITATIONS,
            created_at=run.created_at,
        )
        assert_public_payload(mission)
        self.mission_store.put(mission)
        return mission


def _initial_plan() -> tuple[SuperAgentPlanStep, ...]:
    return (
        SuperAgentPlanStep(
            sequence=1,
            actor=SuperAgentActor.SEMANTIC_ANALYST,
            action_code="inspect_semantic_evidence",
            summary="检查语义安全等级和归一化类别。",
        ),
        SuperAgentPlanStep(
            sequence=2,
            actor=SuperAgentActor.TOKEN_ANALYST,
            action_code="inspect_token_distribution",
            summary="检查 CPD 状态和脱敏异常起点。",
        ),
        SuperAgentPlanStep(
            sequence=3,
            actor=SuperAgentActor.KNOWLEDGE_ANALYST,
            action_code="inspect_grounded_evidence",
            summary="检查官方知识证据和反事实结果。",
        ),
        SuperAgentPlanStep(
            sequence=4,
            actor=SuperAgentActor.COORDINATOR,
            action_code="select_monotonic_response",
            summary="根据不可变基础动作选择内部处置工具。",
        ),
    )


def _append_detection_observations(
    events: list[SuperAgentTraceEvent], run: Any
) -> None:
    detection = run.detection
    severity = _value(detection.semantic_severity)
    categories = tuple(_value(item) for item in detection.semantic_categories)
    _append_event(
        events,
        phase=SuperAgentTracePhase.OBSERVE,
        actor=SuperAgentActor.SEMANTIC_ANALYST,
        status="succeeded",
        summary=f"语义证据已归一化为 {severity}。",
        evidence_codes=(f"semantic:{severity}",)
        + tuple(f"category:{item}" for item in categories),
    )

    span = detection.suspicious_span
    token_codes = [f"cpd:{_value(detection.detector_status)}"]
    if span is not None:
        token_codes.append(f"onset:{span['token_start']}")
    _append_event(
        events,
        phase=SuperAgentTracePhase.OBSERVE,
        actor=SuperAgentActor.TOKEN_ANALYST,
        status="succeeded",
        summary=(
            "Token 分布证据已完成，存在异常候选。"
            if span is not None
            else "Token 分布证据已完成，未定位异常起点。"
        ),
        evidence_codes=tuple(token_codes),
    )

    knowledge_ids = tuple(
        item.knowledge_id for item in detection.knowledge_evidence
    )
    _append_event(
        events,
        phase=SuperAgentTracePhase.OBSERVE,
        actor=SuperAgentActor.KNOWLEDGE_ANALYST,
        status="succeeded" if knowledge_ids else "skipped",
        summary=(
            "知识证据已核验并保留真实知识 ID。"
            if knowledge_ids
            else "当前任务没有可用知识证据，基础判定不受影响。"
        ),
        evidence_codes=(f"knowledge_status:{_value(detection.knowledge_status)}",)
        + tuple(f"knowledge_id:{item}" for item in knowledge_ids),
    )
    _append_event(
        events,
        phase=SuperAgentTracePhase.OBSERVE,
        actor=SuperAgentActor.COORDINATOR,
        status="succeeded",
        summary="反事实敏感性与融合依据已进入重规划。",
        evidence_codes=(
            f"fusion:{_value(detection.fusion_reason)}",
            f"counterfactual:{_value(run.counterfactual.interpretation)}",
        ),
    )


def _append_event(
    events: list[SuperAgentTraceEvent],
    *,
    phase: SuperAgentTracePhase,
    actor: SuperAgentActor,
    status: str,
    summary: str,
    evidence_codes: Sequence[str],
    tool_id: LabToolId | None = None,
) -> None:
    events.append(
        SuperAgentTraceEvent(
            sequence=len(events) + 1,
            phase=phase,
            actor=actor,
            status=status,
            summary=summary,
            evidence_codes=tuple(evidence_codes),
            tool_id=tool_id,
        )
    )


def _execution_reference(
    execution: LabToolExecution,
) -> SuperAgentExecutionReference:
    return SuperAgentExecutionReference(
        execution_id=execution.execution_id,
        tool_id=execution.tool_id,
        status=_value(execution.status),
        source_action=execution.source_action,
        effective_action=execution.effective_action,
        receipt_id=execution.receipt_id,
        artifact_id=execution.artifact_id,
        evidence_sha256=execution.evidence_sha256,
    )


def _tool_idempotency_key(mission_id: str, tool_id: LabToolId) -> uuid.UUID:
    return uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"token-sentinel-superagent-v1:{mission_id}:{tool_id.value}",
    )


def _replan_summary(
    decision: Any, tools: Sequence[LabToolId]
) -> str:
    if not tools:
        return "两路基础证据允许请求，不调用处置工具。"
    return (
        f"基础动作 {_value(decision)} 保持不变，选择 "
        f"{len(tools)} 个平台内部工具。"
    )


def _tool_summary(tool_id: LabToolId, status: str) -> str:
    title = {
        LabToolId.GATEWAY_ENFORCEMENT: "内部网关状态",
        LabToolId.SECURITY_CASE: "脱敏安全工单",
        LabToolId.EVIDENCE_BUNDLE: "结构化证据包",
    }[tool_id]
    return f"{title}{'执行成功' if status == 'succeeded' else '执行失败'}。"


def _completion_summary(status: str) -> str:
    return {
        "closed_safe": "任务闭环：证据支持安全放行。",
        "contained": "任务闭环：平台内部响应全部完成。",
        "review_required": "任务闭环：已生成复核工单和证据。",
        "degraded": "任务降级闭环：保留基础动作并记录工具失败。",
    }[status]


def _value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw)
