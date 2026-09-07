from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4

from app.security_agent.education import SecurityEducationService
from app.security_agent.intent import parse_intent
from app.security_agent.models import (
    AgentCapabilities,
    AgentEvent,
    AgentHypothesis,
    AgentMessage,
    AgentObservation,
    AgentReportMetadata,
    AgentTaskSnapshot,
    AgentTaskStatus,
    AgentTaskType,
    AgentTimelineEvent,
)
from app.security_agent.planner import HypothesisEvaluator, SecurityAgentPlanner
from app.security_agent.policy import AgentPlanRejected, validate_plan
from app.security_agent.reporting import render_case_report
from app.security_agent.store import SecurityAgentStore


class AgentAuthorizationScopeMismatch(ValueError):
    pass


class SecurityAgentCoordinator:
    def __init__(
        self,
        *,
        store: SecurityAgentStore,
        registry: Any,
        capabilities: AgentCapabilities,
        planner: SecurityAgentPlanner | None = None,
        education: SecurityEducationService | None = None,
    ) -> None:
        self.store = store
        self.registry = registry
        self.capabilities = capabilities
        self.planner = planner or SecurityAgentPlanner()
        self.education = education or SecurityEducationService()
        self._hypotheses = HypothesisEvaluator()
        self._reports: dict[str, str] = {}
        self._pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="security-agent")
        self._futures: dict[str, Future[AgentTaskSnapshot]] = {}
        self._lock = RLock()
        self._closed = False

    def create(self, message: str) -> AgentTaskSnapshot:
        intent = parse_intent(message, None)
        now = _timestamp()
        task_id = f"task_{uuid4().hex}"
        plan = self.planner.create_plan(intent, self.capabilities)
        conversational = intent.kind in {
            "identity",
            "smalltalk",
            "capabilities",
            "explain_attack",
            "explain_pcap",
            "explain_current_evidence",
            "clarify",
            "out_of_scope",
        }
        status = (
            AgentTaskStatus.COMPLETED
            if conversational
            else AgentTaskStatus.AWAITING_AUTHORIZATION
            if intent.requires_authorization
            else AgentTaskStatus.PLANNED
        )
        messages = [self._placeholder_message(now, task_id)]
        if conversational:
            messages.append(self.education.answer(intent))
        events = [
            AgentEvent(
                task_id=task_id,
                sequence=1,
                phase="understand",
                kind="intent_understood",
                summary=intent.objective_summary,
                created_at=now,
            ),
            AgentEvent(
                task_id=task_id,
                sequence=2,
                phase="plan",
                kind="plan_created" if plan else "answer_prepared",
                summary=(
                    f"已生成 {len(plan)} 步有界计划。"
                    if plan
                    else "当前请求无需调用检测工具。"
                ),
                created_at=now,
            ),
        ]
        snapshot = AgentTaskSnapshot(
            task_id=task_id,
            version=1,
            task_type=intent.task_type or AgentTaskType.KNOWLEDGE_EXPLANATION,
            status=status,
            title=_title_for(intent.task_type),
            objective_summary=intent.objective_summary,
            created_at=now,
            updated_at=now,
            messages=tuple(messages),
            plan=plan,
            hypotheses=_initial_hypotheses(intent.task_type),
            events=tuple(events),
            limitations=_initial_limitations(intent.task_type),
        )
        return self.store.create(snapshot)

    def authorize(self, task_id: str, scopes: tuple[str, ...]) -> AgentTaskSnapshot:
        current = self.store.get(task_id)
        required = _required_scopes(current.task_type)
        selected = frozenset(scopes)
        if not required.issubset(selected):
            raise AgentAuthorizationScopeMismatch(task_id)
        if current.status == AgentTaskStatus.CANCELLED:
            return current
        event = self._event(
            current,
            phase="authorize",
            kind="authorization_accepted",
            summary="已接受与任务目的和范围绑定的授权。",
        )
        return self._save(
            current,
            status=AgentTaskStatus.PLANNED,
            authorization_scopes=tuple(sorted(selected)),
            events=current.events + (event,),
        )

    def start_background(self, task_id: str) -> None:
        with self._lock:
            if self._closed or task_id in self._futures:
                return
            self._futures[task_id] = self._pool.submit(self.run_until_blocked, task_id)

    def run_until_blocked(self, task_id: str) -> AgentTaskSnapshot:
        current = self.store.get(task_id)
        if current.status in {AgentTaskStatus.CANCELLED, AgentTaskStatus.COMPLETED}:
            return current
        try:
            validate_plan(
                current.plan,
                self.capabilities,
                frozenset(current.authorization_scopes),
            )
        except AgentPlanRejected as exc:
            observation = AgentObservation(
                observation_id=f"obs_{uuid4().hex}",
                kind="plan_rejected",
                status="failed",
                summary="计划未通过代码策略校验。",
                observed_at=_timestamp(),
                public_error_code="agent_plan_rejected",
            )
            return self._finish_degraded(current, observation, str(exc))

        current = self._save(current, status=AgentTaskStatus.RUNNING)
        executed_action = False
        verification = "unavailable"
        index = 0
        while index < len(current.plan):
            if self.store.get(task_id).status == AgentTaskStatus.CANCELLED:
                return self.store.get(task_id)
            step = current.plan[index]
            if step.status not in {"waiting", "running"}:
                index += 1
                continue
            running_plan = _replace_step(current.plan, index, step.model_copy(update={"status": "running"}))
            current = self._save(
                current,
                plan=running_plan,
                events=current.events
                + (
                    self._event(
                        current,
                        phase="act",
                        kind="tool_started",
                        summary=f"开始执行 {step.tool_id}。",
                    ),
                ),
            )
            try:
                tool_result = self.registry.execute(
                    step.tool_id, self._arguments_for(step.tool_id, current)
                )
                completed_step = current.plan[index].model_copy(update={"status": "succeeded"})
                plan = _replace_step(current.plan, index, completed_step)
                evidence = _merge_evidence(current.evidence, tool_result.evidence)
                timeline = _merge_timeline(current.timeline, tool_result.evidence)
                observations = current.observations + (tool_result.observation,)
                event = self._event(
                    current,
                    phase="observe",
                    kind="tool_observed",
                    summary=tool_result.observation.summary,
                    evidence_refs=tool_result.observation.evidence_refs,
                )
                evaluated = self._hypotheses.evaluate(
                    current.model_copy(
                        update={
                            "plan": plan,
                            "evidence": evidence,
                            "timeline": timeline,
                            "observations": observations,
                        }
                    ),
                    tool_result.observation,
                )
                current = self._save(
                    current,
                    plan=plan,
                    evidence=evidence,
                    timeline=timeline,
                    observations=observations,
                    hypotheses=evaluated.hypotheses,
                    events=current.events + (event,),
                )
                if step.tool_id == "execute_internal_action":
                    executed_action = True
                if step.tool_id == "verify_response_effect":
                    verification = tool_result.observation.kind.removeprefix("response_")

                revised = self.planner.replan(current, tool_result.observation, self.capabilities)
                if revised != current.plan and current.replan_count < self.capabilities.max_replans:
                    current = self._save(
                        current,
                        plan=revised,
                        replan_count=current.replan_count + 1,
                        events=current.events
                        + (
                            self._event(
                                current,
                                phase="replan",
                                kind="plan_revised",
                                summary=f"观察 {tool_result.observation.kind} 触发了计划修订。",
                                evidence_refs=tool_result.observation.evidence_refs,
                            ),
                        ),
                    )
                    index = 0
                    continue
            except Exception as exc:
                failed = current.plan[index].model_copy(update={"status": "failed"})
                observation = AgentObservation(
                    observation_id=f"obs_{uuid4().hex}",
                    kind="tool_unavailable",
                    status="unavailable",
                    summary=f"{step.tool_id} 暂不可用，任务将降级收口。",
                    observed_at=_timestamp(),
                    tool_id=step.tool_id,
                    retryable=True,
                    public_error_code="agent_tool_unavailable",
                )
                current = self._save(
                    current,
                    plan=_replace_step(current.plan, index, failed),
                    observations=current.observations + (observation,),
                    limitations=current.limitations + (f"工具 {step.tool_id} 未完成。",),
                    events=current.events
                    + (
                        self._event(
                            current,
                            phase="observe",
                            kind="tool_failed",
                            summary=observation.summary,
                        ),
                    ),
                )
                del exc
            index += 1

        has_failures = any(step.status == "failed" for step in current.plan)
        if executed_action and verification == "verified":
            final_status = "contained"
        elif any(item.authenticity == "real" for item in current.evidence):
            final_status = "risk_found"
        elif current.evidence:
            final_status = "inconclusive"
        else:
            final_status = "inconclusive" if has_failures else "safe"
        if executed_action and verification != "verified":
            final_status = "inconclusive"
        report_text = render_case_report(
            title=current.title,
            objective=current.objective_summary,
            evidence=current.evidence,
            hypotheses=current.hypotheses,
            limitations=current.limitations,
            final_status=final_status,
        )
        report_id = f"report_{uuid4().hex}"
        self._reports[report_id] = report_text
        report = AgentReportMetadata(
            report_id=report_id,
            title=f"{current.title}报告",
            status="degraded" if has_failures else "ready",
            artifact_ref=f"agent-report:{report_id}",
            evidence_refs=tuple(item.evidence_id for item in current.evidence),
            generated_at=_timestamp(),
        )
        completed_event = self._event(
            current,
            phase="complete",
            kind="task_completed" if not has_failures else "task_degraded",
            summary="调查完成并生成可审计报告。" if not has_failures else "调查以降级状态完成。",
            evidence_refs=report.evidence_refs,
        )
        return self._save(
            current,
            status=AgentTaskStatus.DEGRADED if has_failures else AgentTaskStatus.COMPLETED,
            final_status=final_status,
            report=report,
            events=current.events + (completed_event,),
        )

    def add_message(self, task_id: str, message: str) -> AgentTaskSnapshot:
        current = self.store.get(task_id)
        intent = parse_intent(message, current)
        if intent.kind == "cancel_task":
            return self.cancel(task_id)
        now = _timestamp()
        messages = current.messages + (
            self._placeholder_message(now, task_id),
        )
        if intent.kind in {
            "identity",
            "smalltalk",
            "capabilities",
            "explain_attack",
            "explain_pcap",
            "explain_current_evidence",
            "clarify",
            "out_of_scope",
        }:
            messages += (self.education.answer(intent, current.evidence),)
        else:
            messages += (
                AgentMessage(
                    message_id=f"msg_{uuid4().hex}",
                    role="agent",
                    kind="status",
                    content="已理解后续指令；涉及新范围时需要新的目的绑定授权。",
                    created_at=now,
                    evidence_scope="current_case",
                ),
            )
        return self._save(current, messages=messages)

    def cancel(self, task_id: str) -> AgentTaskSnapshot:
        current = self.store.get(task_id)
        if current.status == AgentTaskStatus.CANCELLED:
            return current
        event = self._event(
            current,
            phase="complete",
            kind="task_cancelled",
            summary="用户已明确取消当前任务。",
        )
        return self._save(
            current,
            status=AgentTaskStatus.CANCELLED,
            events=current.events + (event,),
        )

    def get(self, task_id: str) -> AgentTaskSnapshot:
        return self.store.get(task_id)

    def list(self, *, limit: int, offset: int) -> tuple[AgentTaskSnapshot, ...]:
        return self.store.list(limit=limit, offset=offset)

    def events_after(self, task_id: str, sequence: int) -> tuple[AgentEvent, ...]:
        return self.store.events_after(task_id, sequence)

    def report(self, report_id: str) -> str | None:
        return self._reports.get(report_id)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._pool.shutdown(wait=True, cancel_futures=False)
        self.store.close()

    def _save(self, current: AgentTaskSnapshot, **updates: Any) -> AgentTaskSnapshot:
        next_snapshot = current.model_copy(
            update={
                **updates,
                "version": current.version + 1,
                "updated_at": _timestamp(),
            }
        )
        return self.store.replace(next_snapshot, expected_version=current.version)

    def _event(
        self,
        current: AgentTaskSnapshot,
        *,
        phase: str,
        kind: str,
        summary: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> AgentEvent:
        return AgentEvent(
            task_id=current.task_id,
            sequence=len(current.events) + 1,
            phase=phase,
            kind=kind,
            summary=summary,
            created_at=_timestamp(),
            evidence_refs=evidence_refs,
        )

    @staticmethod
    def _placeholder_message(created_at: str, task_id: str) -> AgentMessage:
        return AgentMessage(
            message_id=f"msg_{uuid4().hex}",
            role="user",
            content="[用户已提交安全任务，原始内容未保存]",
            created_at=created_at,
            evidence_scope="none",
        )

    @staticmethod
    def _arguments_for(tool_id: str, current: AgentTaskSnapshot) -> dict[str, object]:
        first_evidence = current.evidence[0].evidence_id if current.evidence else "evidence:none"
        authorization = current.authorization_scopes[0] if current.authorization_scopes else "authorization:none"
        if tool_id in {"analyze_prompt", "counterfactual_recheck"}:
            return {"input_ref": f"transient:{current.task_id}"}
        if tool_id in {"inspect_pcap_dataset", "detect_pcap_batch"}:
            arguments: dict[str, object] = {"authorization_ref": authorization}
            if tool_id == "detect_pcap_batch":
                arguments["start_index"] = 0
            return arguments
        if tool_id == "explain_pcap_capture":
            return {"evidence_ref": first_evidence}
        if tool_id == "retrieve_security_knowledge":
            return {"evidence_ref": first_evidence}
        if tool_id == "explain_attack":
            return {"knowledge_ref": "knowledge:approved"}
        if tool_id in {"explain_protocol", "map_attack_framework", "search_similar_cases"}:
            return {"evidence_ref": first_evidence}
        if tool_id in {"generate_case_report", "preview_response_action", "simulate_response_options"}:
            return {"task_ref": current.task_id}
        if tool_id == "execute_internal_action":
            return {"authorization_ref": authorization, "action_ref": f"action:{current.task_id}"}
        if tool_id == "verify_response_effect":
            return {"action_ref": f"action:{current.task_id}"}
        if tool_id == "query_simulated_telemetry":
            return {"case_id": "demo_llm_injection_01"}
        if tool_id == "record_analyst_feedback":
            return {"authorization_ref": authorization, "task_ref": current.task_id}
        if tool_id == "inspect_encrypted_flow_behavior":
            return {"authorization_ref": authorization}
        return {}

    def _finish_degraded(
        self, current: AgentTaskSnapshot, observation: AgentObservation, limitation: str
    ) -> AgentTaskSnapshot:
        return self._save(
            current,
            status=AgentTaskStatus.DEGRADED,
            final_status="inconclusive",
            observations=current.observations + (observation,),
            limitations=current.limitations + (limitation,),
        )


def _replace_step(plan, index: int, replacement):
    values = list(plan)
    values[index] = replacement
    return tuple(values)


def _merge_evidence(existing, new_items):
    values = {item.evidence_id: item for item in existing}
    values.update({item.evidence_id: item for item in new_items})
    return tuple(values.values())


def _merge_timeline(existing, evidence_items):
    values = {item.timeline_id: item for item in existing}
    for evidence in evidence_items:
        timeline_id = f"timeline_{evidence.evidence_id}"
        values[timeline_id] = AgentTimelineEvent(
            timeline_id=timeline_id,
            occurred_at=evidence.observed_at,
            source_type=evidence.source_type,
            authenticity=evidence.authenticity,
            summary=evidence.summary,
            evidence_refs=(evidence.evidence_id,),
        )
    return tuple(values.values())


def _required_scopes(task_type: AgentTaskType) -> frozenset[str]:
    if task_type in {
        AgentTaskType.PCAP_DATASET_INVESTIGATION,
        AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
    }:
        return frozenset({"pcap:read"})
    if task_type is AgentTaskType.PROMPT_INVESTIGATION:
        return frozenset({"prompt:analyze"})
    if task_type is AgentTaskType.CROSS_DOMAIN_CASE:
        return frozenset({"demo:use", "response:execute"})
    return frozenset()


def _initial_hypotheses(task_type: AgentTaskType | None) -> tuple[AgentHypothesis, ...]:
    if task_type not in {
        AgentTaskType.PROMPT_INVESTIGATION,
        AgentTaskType.PCAP_DATASET_INVESTIGATION,
        AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
        AgentTaskType.CROSS_DOMAIN_CASE,
    }:
        return ()
    return (
        AgentHypothesis(
            hypothesis_id="hyp_01",
            title="存在恶意攻击或侦察行为",
            status="investigating",
            confidence=0.35,
            limitations=("等待直接检测证据。",),
        ),
        AgentHypothesis(
            hypothesis_id="hyp_02",
            title="正常业务波动或规则误报",
            status="investigating",
            confidence=0.45,
            limitations=("等待反证和响应侧观察。",),
        ),
    )


def _initial_limitations(task_type: AgentTaskType | None) -> tuple[str, ...]:
    if task_type is AgentTaskType.CROSS_DOMAIN_CASE:
        return ("端点、身份与日志证据来自明确标注的内置仿真连接器。",)
    if task_type in {
        AgentTaskType.PCAP_DATASET_INVESTIGATION,
        AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
    }:
        return ("加密负载不可见；检测候选不等同于攻击成功。",)
    return ("结论仅覆盖当前授权的数据源。",)


def _title_for(task_type: AgentTaskType | None) -> str:
    return {
        AgentTaskType.PROMPT_INVESTIGATION: "Prompt 安全调查",
        AgentTaskType.PCAP_DATASET_INVESTIGATION: "PCAP 数据集调查",
        AgentTaskType.PCAP_CAPTURE_INVESTIGATION: "PCAP 单文件调查",
        AgentTaskType.CROSS_DOMAIN_CASE: "跨域安全案件",
        AgentTaskType.REPORT_GENERATION: "安全报告",
    }.get(task_type, "安全知识对话")


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
