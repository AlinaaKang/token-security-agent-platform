from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from threading import Lock
from typing import Any

from app.demo.service import DemoSampleNotFound
from app.lab.counterfactual import CounterfactualRunner
from app.lab.models import (
    LabDetectionSnapshot,
    LabLatencySummary,
    LabMetrics,
    LabRunRequest,
    LabRunResult,
    LabScenario,
    LabStage,
    LabToolId,
    assert_public_payload,
)
from app.lab.reporting import build_case_report
from app.lab.store import LabRunStore
from app.lab.tools import build_response_plan, execute_dry_run
from app.schemas import AnalysisRequest, AnalysisResult


logger = logging.getLogger(__name__)


_SYNTHETIC_SCENARIOS = {
    "synthetic_safe": (
        "普通无害",
        "Explain why input validation is useful in a web application.",
    ),
    "synthetic_shift": (
        "无害格式突变",
        "Summarize input validation:\n\n### CHECKLIST ###\n1. Types\n2. Lengths\n3. Encoding",
    ),
}

_PROTECTED_FAMILY_ORDER = (
    ("direct_unsafe", "直接危险"),
    ("gcg", "GCG 优化攻击"),
    ("autodan", "AutoDAN 优化攻击"),
    ("advprompter", "AdvPrompter 优化攻击"),
)


class LabRunCreationFailed(RuntimeError):
    pass


class LabService:
    def __init__(
        self,
        *,
        workflow: Any,
        demo_service: Any | None = None,
        run_store: LabRunStore[LabRunResult] | None = None,
    ) -> None:
        self.workflow = workflow
        self.demo_service = demo_service
        self.run_store = run_store or LabRunStore()
        self.counterfactual_runner = CounterfactualRunner(workflow)
        self._privacy_lock = Lock()
        self._privacy_violation_count = 0

    def list_scenarios(self) -> tuple[LabScenario, ...]:
        scenarios = [
            LabScenario(
                scenario_id=scenario_id,
                label=label,
                scenario_kind="synthetic",
            )
            for scenario_id, (label, _) in _SYNTHETIC_SCENARIOS.items()
        ]
        if self.demo_service is None:
            return tuple(scenarios)
        for family, label in _PROTECTED_FAMILY_ORDER:
            family_samples = self.demo_service.list_samples(family=family, limit=1)
            selected = family_samples[0] if family_samples else None
            if selected is not None:
                scenarios.append(
                    LabScenario(
                        scenario_id=selected.sample_id,
                        label=label,
                        scenario_kind="protected",
                        attack_family=selected.family,
                    )
                )
        return tuple(scenarios)

    def create_run(self, request: LabRunRequest) -> LabRunResult:
        run_id = f"lab_{uuid.uuid4().hex}"
        input_length = 0
        input_hash = "unavailable"
        try:
            if request.scenario_kind == "custom":
                source = request.custom_input or ""
                input_length = len(source)
                input_hash = _sha256_text(source)
                analysis = self.workflow.analyze(
                    AnalysisRequest(
                        prompt=source,
                        model_id=self.workflow.calibration.model_id,
                        mode=request.mode,
                        knowledge_mode="report",
                    ),
                    request_id=f"lab_base_{uuid.uuid4().hex}",
                )
                counterfactual = self.counterfactual_runner.run(
                    prompt=source,
                    original=analysis,
                    mode=request.mode,
                )
                scenario_id = "custom"
                scenario_kind = "custom"
                scenario_label = "自定义输入"
                attack_family = None
            elif request.sample_id in _SYNTHETIC_SCENARIOS:
                scenario_id = request.sample_id
                scenario_label, source = _SYNTHETIC_SCENARIOS[scenario_id]
                input_length = len(source)
                input_hash = _sha256_text(source)
                analysis = self.workflow.analyze(
                    AnalysisRequest(
                        prompt=source,
                        model_id=self.workflow.calibration.model_id,
                        mode=request.mode,
                        knowledge_mode="report",
                    ),
                    request_id=f"lab_base_{uuid.uuid4().hex}",
                )
                counterfactual = self.counterfactual_runner.run(
                    prompt=source,
                    original=analysis,
                    mode=request.mode,
                )
                scenario_kind = "synthetic"
                attack_family = None
            else:
                if self.demo_service is None or request.sample_id is None:
                    raise DemoSampleNotFound(request.sample_id or "missing")
                scenario_id = request.sample_id
                attack_family, analysis, counterfactual = (
                    self.demo_service.analyze_for_lab(
                        scenario_id,
                        self.workflow,
                        mode=request.mode,
                        counterfactual_runner=self.counterfactual_runner,
                    )
                )
                scenario_kind = "protected"
                scenario_label = _protected_label(attack_family)

            run = self._assemble_run(
                run_id=run_id,
                scenario_id=scenario_id,
                scenario_kind=scenario_kind,
                scenario_label=scenario_label,
                attack_family=attack_family,
                mode=request.mode,
                analysis=analysis,
                counterfactual=counterfactual,
            )
            self.run_store.put(run)
            logger.info(
                "lab run completed run_id=%s input_sha256=%s input_chars=%d status=completed",
                run_id,
                input_hash,
                input_length,
            )
            return run
        except Exception as exc:
            logger.error(
                "lab run failed run_id=%s input_sha256=%s input_chars=%d error_type=%s",
                run_id,
                input_hash,
                input_length,
                type(exc).__name__,
            )
            raise LabRunCreationFailed("lab_run_failed") from None

    def get_run(self, run_id: str) -> LabRunResult:
        return self.run_store.get(run_id)

    def run_tool(
        self,
        run_id: str,
        tool_id: LabToolId | str,
        *,
        inject_failure: bool,
    ) -> LabRunResult:
        selected_tool = LabToolId(tool_id)
        run = self.run_store.get(run_id)
        plan = next(
            item for item in run.tool_plans if item.tool_id is selected_tool
        )
        result = execute_dry_run(plan, inject_failure=inject_failure)
        tool_results = tuple(
            item for item in run.tool_results if item.tool_id is not selected_tool
        ) + (result,)
        report = build_case_report(
            decision=run.detection.decision,
            evidence=run.detection.knowledge_evidence,
            counterfactual=run.counterfactual,
            tool_results=tool_results,
            requested_evidence_ids=tuple(
                item.knowledge_id for item in run.detection.knowledge_evidence
            ),
        )
        updated = run.model_copy(
            update={"tool_results": tool_results, "case_report": report}
        )
        self._validate_public(updated)
        self.run_store.put(updated)
        return updated

    def metrics(self) -> LabMetrics:
        runs = self.run_store.snapshot()
        run_count = len(runs)
        eligible = sum(run.counterfactual.char_start is not None for run in runs)
        executed = sum(run.counterfactual.rechecked is not None for run in runs)
        agreement = sum(_evidence_relation(run) == "agreement" for run in runs)
        conflict = sum(_evidence_relation(run) == "conflict" for run in runs)
        tool_results = [result for run in runs for result in run.tool_results]
        tool_success = sum(result.status == "succeeded" for result in tool_results)
        tool_failure = sum(result.status == "failed" for result in tool_results)
        generated = sum(run.case_report.report_status == "deterministic" for run in runs)
        fallback = sum(run.case_report.report_status == "fallback" for run in runs)
        invariant = sum(
            all(
                result.effective_action == run.detection.decision
                for result in run.tool_results
            )
            for run in runs
        )
        latencies = [run.detection.latency_ms for run in runs]
        metrics = LabMetrics(
            run_count=run_count,
            counterfactual_eligible_count=eligible,
            counterfactual_executed_count=executed,
            counterfactual_execution_rate=_rate(executed, eligible),
            evidence_agreement_count=agreement,
            evidence_conflict_count=conflict,
            evidence_conflict_rate=_rate(conflict, agreement + conflict),
            tool_success_count=tool_success,
            tool_failure_count=tool_failure,
            tool_success_rate=_rate(tool_success, tool_success + tool_failure),
            report_generated_count=generated,
            report_fallback_count=fallback,
            action_invariance_count=invariant,
            action_invariance_rate=_rate(invariant, run_count),
            latency_ms=LabLatencySummary(
                p50=_percentile(latencies, 0.5),
                p95=_percentile(latencies, 0.95),
            ),
            privacy_violation_count=self._privacy_violations(),
        )
        self._validate_public(metrics)
        return metrics

    def _validate_public(self, payload: Any) -> None:
        try:
            assert_public_payload(payload)
        except ValueError:
            with self._privacy_lock:
                self._privacy_violation_count += 1
            raise

    def _privacy_violations(self) -> int:
        with self._privacy_lock:
            return self._privacy_violation_count

    def _assemble_run(
        self,
        *,
        run_id: str,
        scenario_id: str,
        scenario_kind: str,
        scenario_label: str,
        attack_family: str | None,
        mode: str,
        analysis: AnalysisResult,
        counterfactual: Any,
    ) -> LabRunResult:
        detection = LabDetectionSnapshot.from_analysis(analysis)
        plans = build_response_plan(
            decision=analysis.decision,
            fusion_reason=analysis.fusion_reason,
            mode=mode,
            evidence=analysis.knowledge_evidence,
        )
        evidence_ids = tuple(
            item.knowledge_id for item in analysis.knowledge_evidence
        )
        report = build_case_report(
            decision=analysis.decision,
            evidence=analysis.knowledge_evidence,
            counterfactual=counterfactual,
            tool_results=(),
            requested_evidence_ids=evidence_ids,
        )
        run = LabRunResult(
            run_id=run_id,
            scenario_id=scenario_id,
            scenario_kind=scenario_kind,
            scenario_label=scenario_label,
            attack_family=attack_family,
            mode=mode,
            created_at=datetime.now(UTC).isoformat(),
            stages=_stages(analysis),
            detection=detection,
            counterfactual=counterfactual,
            tool_plans=plans,
            case_report=report,
        )
        self._validate_public(run)
        return run


def _stages(result: AnalysisResult) -> tuple[LabStage, ...]:
    combined_detection = max(
        result.latency_ms - result.semantic_latency_ms - result.knowledge_latency_ms,
        0.0,
    )
    knowledge_ready = result.knowledge_status.value in {"ready", "degraded"}
    return (
        LabStage(
            stage_id="semantic_guard",
            status=(
                "unavailable"
                if result.semantic_severity.value == "unavailable"
                else "succeeded"
            ),
            latency_ms=result.semantic_latency_ms,
            timing_basis="measured",
            summary="语义安全等级与类别已归一化。",
        ),
        LabStage(
            stage_id="token_observation",
            status="succeeded",
            latency_ms=combined_detection,
            timing_basis="combined",
            summary="Token 观测与 CPD 使用组合耗时。",
        ),
        LabStage(
            stage_id="entropy_cpd",
            status="succeeded",
            timing_basis="unavailable",
            summary="Entropy-CPD 产生异常候选和预测起点。",
        ),
        LabStage(
            stage_id="fixed_fusion",
            status="succeeded",
            timing_basis="unavailable",
            summary="固定融合表生成基础动作。",
        ),
        LabStage(
            stage_id="knowledge_retrieval",
            status="succeeded" if knowledge_ready else "unavailable",
            latency_ms=(result.knowledge_latency_ms if knowledge_ready else None),
            timing_basis="measured" if knowledge_ready else "unavailable",
            summary=(
                "本地知识证据已附加，且不改变基础动作。"
                if knowledge_ready
                else "知识层不可用，保留基础检测结果。"
            ),
        ),
    )


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _protected_label(family: str) -> str:
    normalized = family.casefold()
    for expected, label in _PROTECTED_FAMILY_ORDER:
        if normalized == expected:
            return label
    return f"{family} 冻结样本"


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + fraction * (ordered[upper] - ordered[lower])


def _evidence_relation(run: LabRunResult) -> str:
    semantic_severity = run.detection.semantic_severity.value
    if semantic_severity not in {"safe", "unsafe"}:
        return "unavailable"
    semantic_alert = semantic_severity == "unsafe"
    cpd_alert = run.detection.detector_status == "token_anomaly_candidate"
    return "agreement" if semantic_alert == cpd_alert else "conflict"
