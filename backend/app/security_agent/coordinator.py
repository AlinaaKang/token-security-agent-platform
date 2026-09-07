from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4

from app.pcap.detection_models import PcapDetectionMissionResult
from app.security_agent.dialogue import GroundedDialogueService
from app.security_agent.education import SecurityEducationService
from app.security_agent.intent import extract_prompt_sample, parse_intent
from app.security_agent.models import (
    AgentCapabilities,
    AgentActionRequest,
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
from app.security_agent.pcap_import import import_pcap_detection
from app.security_agent.policy import AgentPlanRejected, validate_plan
from app.security_agent.reporting import render_case_report
from app.security_agent.recommendations import recommendations_for
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
        prompt_runtime: Any | None = None,
        dialogue: GroundedDialogueService | None = None,
    ) -> None:
        self.store = store
        self.registry = registry
        self.capabilities = capabilities
        self.planner = planner or SecurityAgentPlanner()
        self.education = education or SecurityEducationService()
        self.prompt_runtime = prompt_runtime
        self.dialogue = dialogue or GroundedDialogueService(None)
        self._hypotheses = HypothesisEvaluator()
        self._reports: dict[str, str] = {}
        self._pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="security-agent")
        self._futures: dict[str, Future[AgentTaskSnapshot]] = {}
        self._lock = RLock()
        self._closed = False

    def create(self, message: str, *, workspace_mode: str | None = None) -> AgentTaskSnapshot:
        intent = parse_intent(message, None, workspace_mode=workspace_mode)
        resolved_workspace = workspace_mode or (
            "pcap"
            if intent.task_type in {
                AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
                AgentTaskType.PCAP_DATASET_INVESTIGATION,
            }
            else "prompt"
        )
        if resolved_workspace not in {"prompt", "pcap"}:
            raise ValueError("agent_workspace_invalid")
        now = _timestamp()
        task_id = f"task_{uuid4().hex}"
        if intent.task_type is AgentTaskType.PROMPT_INVESTIGATION and self.prompt_runtime is not None:
            self.prompt_runtime.put(task_id, extract_prompt_sample(message))
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
        messages = [self._user_message(now, message)]
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
            workspace_mode=resolved_workspace,
            status=status,
            title=_title_for(intent.task_type, message),
            objective_summary=intent.objective_summary,
            created_at=now,
            updated_at=now,
            messages=tuple(messages),
            plan=plan,
            hypotheses=_initial_hypotheses(intent.task_type),
            events=tuple(events),
            limitations=_initial_limitations(intent.task_type),
        )
        questions, actions = recommendations_for(snapshot, self.capabilities)
        snapshot = snapshot.model_copy(
            update={"suggested_questions": questions, "next_actions": actions}
        )
        return self.store.create(snapshot)

    def create_from_pcap(
        self,
        result: PcapDetectionMissionResult,
        *,
        task_id: str | None = None,
    ) -> tuple[AgentTaskSnapshot, bool]:
        imported = import_pcap_detection(result)
        marker = f"已导入公开 PCAP 检测结果 {imported.source_ref}。"
        if task_id is not None:
            current = self.store.get(task_id)
            if current.workspace_mode != "pcap":
                raise ValueError("pcap_target_workspace_mismatch")
            if any(
                event.kind == "pcap_detection_imported" and event.summary == marker
                for event in current.events
            ):
                return current, False
            return self._append_pcap_import(current, imported, marker), False

        offset = 0
        while True:
            page = self.store.list(limit=100, offset=offset)
            for existing in page:
                if any(event.kind == "pcap_detection_imported" and event.summary == marker for event in existing.events):
                    return existing, False
            if len(page) < 100:
                break
            offset += 100

        now = _timestamp()
        task_id = f"task_{uuid4().hex}"
        snapshot = AgentTaskSnapshot(
            task_id=task_id,
            version=1,
            task_type=AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
            workspace_mode="pcap",
            status=AgentTaskStatus.DEGRADED if imported.degraded else AgentTaskStatus.COMPLETED,
            title=f"PCAP 数据调查 · {result.created_at[5:16].replace('T', ' ')}",
            objective_summary="定位异常 Packet、研判攻击类型与目的，并形成可继续追问的调查结论。",
            created_at=now,
            updated_at=now,
            messages=(
                self._user_message(now, "调查刚刚完成的 PCAP 检测结果"),
                AgentMessage(
                    message_id=f"msg_{uuid4().hex}",
                    role="agent",
                    kind="result",
                    content=imported.result_text,
                    created_at=now,
                    evidence_scope="current_case",
                    evidence_refs=tuple(item.evidence_id for item in imported.evidence),
                ),
            ),
            plan=imported.plan,
            observations=imported.observations,
            evidence=imported.evidence,
            hypotheses=imported.hypotheses,
            timeline=imported.timeline,
            events=(
                AgentEvent(task_id=task_id, sequence=1, phase="understand", kind="pcap_detection_imported", summary=marker, created_at=now, evidence_refs=tuple(item.evidence_id for item in imported.evidence)),
                AgentEvent(task_id=task_id, sequence=2, phase="complete", kind="task_degraded" if imported.degraded else "task_completed", summary=imported.result_text, created_at=now, evidence_refs=tuple(item.evidence_id for item in imported.evidence)),
            ),
            final_status=imported.final_status,
            limitations=imported.limitations,
        )
        questions, actions = recommendations_for(snapshot, self.capabilities)
        snapshot = snapshot.model_copy(update={"suggested_questions": questions, "next_actions": actions})
        return self.store.create(snapshot), True

    def _append_pcap_import(
        self,
        current: AgentTaskSnapshot,
        imported: Any,
        marker: str,
    ) -> AgentTaskSnapshot:
        now = _timestamp()
        evidence_refs = tuple(item.evidence_id for item in imported.evidence)
        messages = current.messages + (
            self._user_message(now, "上传并调查新的 PCAP 文件"),
            AgentMessage(
                message_id=f"msg_{uuid4().hex}",
                role="agent",
                kind="result",
                content=imported.result_text,
                created_at=now,
                evidence_scope="current_case",
                evidence_refs=evidence_refs,
            ),
        )
        events = current.events + (
            self._event(
                current,
                phase="understand",
                kind="pcap_detection_imported",
                summary=marker,
                evidence_refs=evidence_refs,
            ),
            AgentEvent(
                task_id=current.task_id,
                sequence=len(current.events) + 2,
                phase="complete",
                kind="task_degraded" if imported.degraded else "task_completed",
                summary=imported.result_text,
                created_at=now,
                evidence_refs=evidence_refs,
            ),
        )
        observations = _merge_by_id(
            current.observations, imported.observations, "observation_id", 200
        )
        evidence = _merge_by_id(current.evidence, imported.evidence, "evidence_id", 200)
        timeline = _merge_by_id(current.timeline, imported.timeline, "timeline_id", 200)
        limitations = tuple(dict.fromkeys(current.limitations + imported.limitations))[-50:]
        return self._save(
            current,
            task_type=AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
            status=AgentTaskStatus.DEGRADED if imported.degraded else AgentTaskStatus.COMPLETED,
            objective_summary="持续接收 PCAP 证据，定位异常 Packet、研判攻击类型与目的。",
            messages=messages[-100:],
            plan=imported.plan,
            observations=observations,
            evidence=evidence,
            hypotheses=imported.hypotheses,
            timeline=timeline,
            events=events[-500:],
            final_status=imported.final_status,
            report=None,
            limitations=limitations,
        )

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
        try:
            return self._run_until_blocked(task_id)
        finally:
            try:
                current = self.store.get(task_id)
            except Exception:
                current = None
            if current is not None and current.status in {
                AgentTaskStatus.COMPLETED,
                AgentTaskStatus.DEGRADED,
                AgentTaskStatus.FAILED,
                AgentTaskStatus.CANCELLED,
            }:
                self._discard_prompt(task_id)

    def _run_until_blocked(self, task_id: str) -> AgentTaskSnapshot:
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
        report = (
            self._generate_report(
                current, degraded=has_failures, final_status=final_status
            )
            if any(
                step.tool_id == "generate_case_report" and step.status == "succeeded"
                for step in current.plan
            )
            else None
        )
        evidence_refs = tuple(item.evidence_id for item in current.evidence)
        completed_event = self._event(
            current,
            phase="complete",
            kind="task_completed" if not has_failures else "task_degraded",
            summary=(
                "调查完成并生成可审计报告。"
                if report is not None
                else "调查完成，等待用户选择下一步。"
            ) if not has_failures else "调查以降级状态完成。",
            evidence_refs=evidence_refs,
        )
        result_message = _completion_message(
            final_status=final_status,
            evidence_refs=evidence_refs,
            has_failures=has_failures,
        )
        return self._save(
            current,
            status=AgentTaskStatus.DEGRADED if has_failures else AgentTaskStatus.COMPLETED,
            final_status=final_status,
            report=report,
            messages=current.messages + (result_message,),
            events=current.events + (completed_event,),
        )

    def execute_action(
        self, task_id: str, request: AgentActionRequest
    ) -> AgentTaskSnapshot:
        current = self.store.get(task_id)
        available = next(
            (
                item
                for item in current.next_actions
                if item.action_id == request.action_id and item.enabled
            ),
            None,
        )
        if available is None:
            raise ValueError("agent_action_not_available")
        now = _timestamp()
        messages = current.messages + (self._user_message(now, available.label),)
        if request.action_id == "generate_report":
            report = self._generate_report(
                current, degraded=current.status is AgentTaskStatus.DEGRADED
            )
            reply = "调查报告已生成，并已加入智能体资源。"
            updated_report = report
        else:
            updated_report = current.report
            reply = _action_reply(request.action_id, current)
        messages += (
            AgentMessage(
                message_id=f"msg_{uuid4().hex}",
                role="agent",
                kind="result",
                content=reply,
                created_at=_timestamp(),
                evidence_scope="current_case",
                evidence_refs=tuple(item.evidence_id for item in current.evidence),
            ),
        )
        return self._save(current, messages=messages, report=updated_report)

    def add_message(self, task_id: str, message: str) -> AgentTaskSnapshot:
        current = self.store.get(task_id)
        intent = parse_intent(message, current)
        if intent.kind == "cancel_task":
            return self.cancel(task_id)
        now = _timestamp()
        messages = current.messages + (
            self._user_message(now, message),
        )
        if intent.kind == "investigate_prompt":
            if self.prompt_runtime is not None:
                self.prompt_runtime.put(task_id, extract_prompt_sample(message))
            plan = self.planner.create_plan(intent, self.capabilities)
            messages += (
                AgentMessage(
                    message_id=f"msg_{uuid4().hex}",
                    role="agent",
                    kind="status",
                    content=f"已识别为 Prompt 安全调查，并生成 {len(plan)} 步检测计划。授权后开始执行。",
                    created_at=now,
                    evidence_scope="current_case",
                ),
            )
            return self._save(
                current,
                task_type=AgentTaskType.PROMPT_INVESTIGATION,
                status=AgentTaskStatus.AWAITING_AUTHORIZATION,
                objective_summary=intent.objective_summary,
                messages=messages,
                plan=plan,
                authorization_scopes=(),
                final_status=None,
                report=None,
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
        elif intent.kind == "case_question":
            messages += (self.dialogue.answer(message, current),)
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
        cancelled = self._save(
            current,
            status=AgentTaskStatus.CANCELLED,
            events=current.events + (event,),
        )
        self._discard_prompt(task_id)
        return cancelled

    def get(self, task_id: str) -> AgentTaskSnapshot:
        return self.store.get(task_id)

    def list(self, *, limit: int, offset: int) -> tuple[AgentTaskSnapshot, ...]:
        return self.store.list(limit=limit, offset=offset)

    def delete(self, task_id: str) -> None:
        self.store.delete(task_id)
        self._discard_prompt(task_id)
        with self._lock:
            self._futures.pop(task_id, None)

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
        if self.prompt_runtime is not None:
            self.prompt_runtime.clear()
        self.store.close()

    def _discard_prompt(self, task_id: str) -> None:
        if self.prompt_runtime is not None:
            self.prompt_runtime.discard(task_id)

    def _save(self, current: AgentTaskSnapshot, **updates: Any) -> AgentTaskSnapshot:
        next_snapshot = current.model_copy(
            update={
                **updates,
                "version": current.version + 1,
                "updated_at": _timestamp(),
            }
        )
        questions, actions = recommendations_for(next_snapshot, self.capabilities)
        next_snapshot = next_snapshot.model_copy(
            update={"suggested_questions": questions, "next_actions": actions}
        )
        return self.store.replace(next_snapshot, expected_version=current.version)

    def _generate_report(
        self,
        current: AgentTaskSnapshot,
        *,
        degraded: bool,
        final_status: str | None = None,
    ) -> AgentReportMetadata:
        report_text = render_case_report(
            title=current.title,
            objective=current.objective_summary,
            evidence=current.evidence,
            hypotheses=current.hypotheses,
            limitations=current.limitations,
            final_status=final_status or current.final_status or "inconclusive",
        )
        report_id = f"report_{uuid4().hex}"
        self._reports[report_id] = report_text
        generated_at = _timestamp()
        return AgentReportMetadata(
            report_id=report_id,
            title=f"{current.title} · {generated_at[:16].replace('T', ' ')}",
            status="degraded" if degraded else "ready",
            artifact_ref=f"agent-report:{report_id}",
            evidence_refs=tuple(item.evidence_id for item in current.evidence),
            generated_at=generated_at,
        )

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
    def _user_message(created_at: str, content: str) -> AgentMessage:
        return AgentMessage(
            message_id=f"msg_{uuid4().hex}",
            role="user",
            content=content,
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
        result_message = _completion_message(
            final_status="inconclusive",
            evidence_refs=tuple(item.evidence_id for item in current.evidence),
            has_failures=True,
        )
        return self._save(
            current,
            status=AgentTaskStatus.DEGRADED,
            final_status="inconclusive",
            observations=current.observations + (observation,),
            limitations=current.limitations + (limitation,),
            messages=current.messages + (result_message,),
        )


def _replace_step(plan, index: int, replacement):
    values = list(plan)
    values[index] = replacement
    return tuple(values)


def _completion_message(
    *, final_status: str, evidence_refs: tuple[str, ...], has_failures: bool
) -> AgentMessage:
    if final_status == "contained":
        content = "调查与处置验证完成：已发现风险，授权处置经独立验证生效。"
    elif final_status == "risk_found":
        content = (
            "调查完成：发现异常候选。请结合证据与限制复核；"
            "异常候选不等于攻击已经成功。"
        )
    elif final_status == "safe":
        content = "调查完成：当前检测范围内未发现异常候选。检测未命中不等于全部安全。"
    else:
        content = (
            "调查已结束，但证据不足或部分工具失败，当前结论不确定。"
            "请查看失败项、限制和报告后重试或补充数据。"
        )
    if has_failures and final_status != "inconclusive":
        content += " 部分工具未完成，结论需要人工复核。"
    return AgentMessage(
        message_id=f"msg_{uuid4().hex}",
        role="agent",
        kind="result",
        content=content,
        created_at=_timestamp(),
        evidence_scope="current_case",
        evidence_refs=evidence_refs,
    )


def _action_reply(action_id: str, current: AgentTaskSnapshot) -> str:
    evidence = "；".join(item.summary for item in current.evidence[:3])
    if action_id in {"explain_evidence", "inspect_suspicious_packets"}:
        return f"当前可复核证据：{evidence or '当前没有可定位的公开证据。'}"
    if action_id == "suggest_prompt_repair":
        return "修复方案：保留业务目标，删除要求忽略规则、泄露指令或越权调用工具的内容，并对外部输入增加明确数据边界。"
    if action_id == "recheck_prompt":
        return "请在输入框中粘贴修复后的 Prompt；原始内容不会从服务端历史中恢复。"
    if action_id == "analyze_attack_chain":
        return f"攻击链研判基于当前公开时序证据：{evidence or '证据不足，暂时无法建立攻击链。'}"
    if action_id == "generate_response_plan":
        return "建议先保全证据并复核异常 Packet，再按影响范围选择限流、隔离或封禁；真实外部处置仍需连接器与单独授权。"
    if action_id == "expand_pcap_scope":
        return "扩大 PCAP 调查范围需要重新选择数据并授权，当前任务不会自动读取范围外文件。"
    return "当前动作已完成。"


def _merge_evidence(existing, new_items):
    values = {item.evidence_id: item for item in existing}
    values.update({item.evidence_id: item for item in new_items})
    return tuple(values.values())


def _merge_by_id(existing, new_items, attribute, limit):
    values = {getattr(item, attribute): item for item in existing}
    values.update({getattr(item, attribute): item for item in new_items})
    return tuple(values.values())[-limit:]


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


def _title_for(task_type: AgentTaskType | None, message: str) -> str:
    compact = " ".join(message.split())
    if task_type is AgentTaskType.PROMPT_INVESTIGATION:
        if "越狱" in compact:
            return "Prompt 越狱风险调查"
        if "注入" in compact:
            return "Prompt 注入风险调查"
        return "Prompt 安全调查"
    if task_type in {
        AgentTaskType.PCAP_DATASET_INVESTIGATION,
        AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
    }:
        safe = compact.split("：", 1)[0].split(":", 1)[0]
        return safe[:28] + ("…" if len(safe) > 28 else "")
    if task_type is AgentTaskType.CROSS_DOMAIN_CASE:
        return "跨域安全案件"
    if task_type is AgentTaskType.REPORT_GENERATION:
        return "安全报告"
    return compact[:28] + ("…" if len(compact) > 28 else "")


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
