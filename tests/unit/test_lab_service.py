from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.lab.models import (
    CounterfactualResult,
    CounterfactualSnapshot,
    LabRunRequest,
    assert_public_payload,
)
from app.lab.service import LabRunCreationFailed, LabService
from app.schemas import AnalysisResult, Decision, Provenance, TokenSignal


def _analysis(
    *,
    request_id: str = "req_base",
    decision: str = "block",
    risk_score: float = 0.9,
    detector_score: float = 9.0,
    char_start: int | None = 12,
    with_knowledge: bool = True,
) -> AnalysisResult:
    evidence = []
    if with_knowledge:
        evidence = [
            {
                "knowledge_id": "owasp-llm01-prompt-injection",
                "title_zh": "提示词注入控制",
                "risk_domain": "prompt_injection",
                "summary": "使用分层控制限制提示词注入风险。",
                "recommendations": ["保留基础检测动作。"],
                "source": {
                    "publisher": "owasp",
                    "title": "OWASP GenAI Security Project",
                    "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                    "version": "2025",
                    "verified_at": "2026-08-26T00:00:00Z",
                    "usage_note": "official summary",
                },
                "retrieval_score": 4.0,
                "matched_tags": ["jailbreak"],
            }
        ]
    return AnalysisResult(
        request_id=request_id,
        decision=decision,
        risk_score=risk_score,
        detector_score=detector_score,
        detector_status=(
            "token_anomaly_candidate"
            if detector_score >= 5
            else "no_token_anomaly"
        ),
        semantic_severity="unsafe" if decision == "block" else "safe",
        semantic_categories=["jailbreak"] if decision == "block" else [],
        semantic_model_id="guard-model",
        semantic_model_version="guard-v1",
        semantic_latency_ms=4.0,
        semantic_verification="performed",
        fusion_reason="semantic_unsafe" if decision == "block" else "all_clear",
        suspicious_span=(
            {
                "token_start": 2,
                "token_end": 4,
                "char_start": char_start,
                "char_end": 30,
            }
            if char_start is not None
            else None
        ),
        signals=[
            TokenSignal(
                index=0,
                token_id=42,
                token_text="PRIVATE_TOKEN_TEXT",
                entropy=2.0,
                nll=3.0,
                cpd_entropy=5.0,
                cpd_nll=0.0,
                risk=1.0,
            )
        ],
        evidence=[],
        actions=[decision],
        provenance=Provenance(
            model_id="qwen-model",
            tokenizer_id="qwen-tokenizer",
            system_prompt_hash="sha256:system",
            calibration_version="cal-v2",
            thresholds={"k": 0.5, "h": 5.0},
        ),
        latency_ms=30.0,
        knowledge_status="ready" if with_knowledge else "unavailable",
        knowledge_snapshot_version="official-v1" if with_knowledge else None,
        knowledge_latency_ms=3.0 if with_knowledge else 0.0,
        knowledge_retrieval_latency_ms=2.0 if with_knowledge else 0.0,
        knowledge_report_latency_ms=1.0 if with_knowledge else 0.0,
        knowledge_evidence=evidence,
        report_status="fallback" if with_knowledge else "unavailable",
    )


class RecordingWorkflow:
    class Calibration:
        model_id = "qwen-model"

    calibration = Calibration()

    def __init__(self, *, fail: bool = False, with_knowledge: bool = True) -> None:
        self.fail = fail
        self.with_knowledge = with_knowledge
        self.calls: list[object] = []

    def analyze(self, request: object, *, request_id: str) -> AnalysisResult:
        self.calls.append(request)
        if self.fail:
            raise RuntimeError("PRIVATE_RUNTIME_ERROR")
        if request.knowledge_mode.value == "off":
            return _analysis(
                request_id=request_id,
                decision="allow",
                risk_score=0.2,
                detector_score=1.0,
                char_start=None,
                with_knowledge=False,
            )
        return _analysis(request_id=request_id, with_knowledge=self.with_knowledge)


def _protected_counterfactual() -> CounterfactualResult:
    original = CounterfactualSnapshot(
        semantic_severity="unsafe",
        detector_status="token_anomaly_candidate",
        risk_score=0.9,
        detector_score=9.0,
        decision="block",
        latency_ms=30.0,
    )
    return CounterfactualResult(
        interpretation="risk_reduced",
        reason="completed",
        char_start=12,
        calibration_version="cal-v2",
        original=original,
        rechecked=original.model_copy(
            update={
                "risk_score": 0.2,
                "detector_score": 1.0,
                "decision": Decision.ALLOW,
            }
        ),
        risk_score_delta=0.7,
        detector_score_delta=8.0,
        action_changed=True,
    )


class ProtectedDemoService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def list_samples(self, *, family: str | None, limit: int):
        return [
            SimpleNamespace(sample_id="direct_01", family="direct_unsafe"),
            SimpleNamespace(sample_id="gcg_01", family="gcg"),
            SimpleNamespace(sample_id="autodan_01", family="autodan"),
            SimpleNamespace(sample_id="adv_01", family="advprompter"),
        ][:limit]

    def analyze_for_lab(
        self,
        sample_id: str,
        workflow: object,
        *,
        mode: str,
        counterfactual_runner: object,
    ):
        self.calls.append((sample_id, mode))
        family = next(
            item.family
            for item in self.list_samples(family=None, limit=100)
            if item.sample_id == sample_id
        )
        return family, _analysis(), _protected_counterfactual()


def test_lab_lists_safe_synthetic_and_protected_id_scenarios_without_text() -> None:
    service = LabService(
        workflow=RecordingWorkflow(), demo_service=ProtectedDemoService()
    )

    scenarios = service.list_scenarios()

    assert [item.scenario_id for item in scenarios] == [
        "synthetic_safe",
        "synthetic_shift",
        "direct_01",
        "gcg_01",
        "autodan_01",
        "adv_01",
    ]
    assert all(item.ready for item in scenarios)
    serialized = "".join(item.model_dump_json() for item in scenarios)
    assert "PRIVATE" not in serialized
    assert "custom_input" not in serialized


def test_custom_run_executes_real_sequence_and_stores_only_public_signals() -> None:
    workflow = RecordingWorkflow()
    service = LabService(workflow=workflow)

    run = service.create_run(
        LabRunRequest(
            scenario_kind="custom",
            custom_input="Safe prefix. PRIVATE_CONTINUATION",
            mode="gateway",
        )
    )

    assert len(workflow.calls) == 2
    assert workflow.calls[0].knowledge_mode.value == "report"
    assert workflow.calls[1].knowledge_mode.value == "off"
    assert [stage.stage_id for stage in run.stages] == [
        "semantic_guard",
        "token_observation",
        "entropy_cpd",
        "fixed_fusion",
        "knowledge_retrieval",
    ]
    assert run.detection.signals[0].model_dump() == {
        "index": 0,
        "entropy": 2.0,
        "nll": 3.0,
        "cpd_entropy": 5.0,
        "cpd_nll": 0.0,
        "risk": 1.0,
    }
    assert run.counterfactual.interpretation == "risk_reduced"
    assert run.case_report.evidence_ids == ("owasp-llm01-prompt-injection",)
    serialized = run.model_dump_json()
    assert "PRIVATE_CONTINUATION" not in serialized
    assert "PRIVATE_TOKEN_TEXT" not in serialized
    assert service.get_run(run.run_id) == run


def test_frozen_run_delegates_by_id_without_receiving_protected_text() -> None:
    demo = ProtectedDemoService()
    service = LabService(workflow=RecordingWorkflow(), demo_service=demo)

    run = service.create_run(
        LabRunRequest(
            scenario_kind="frozen",
            sample_id="autodan_01",
            mode="analysis",
        )
    )

    assert demo.calls == [("autodan_01", "analysis")]
    assert run.attack_family == "autodan"
    assert run.scenario_id == "autodan_01"
    assert "PRIVATE" not in run.model_dump_json()


def test_safe_synthetic_scenario_uses_internal_benign_text_without_returning_it() -> None:
    workflow = RecordingWorkflow()
    service = LabService(workflow=workflow)

    run = service.create_run(
        LabRunRequest(
            scenario_kind="frozen",
            sample_id="synthetic_safe",
            mode="analysis",
        )
    )

    assert len(workflow.calls) >= 1
    assert run.scenario_id == "synthetic_safe"
    assert "Explain why" not in run.model_dump_json()


def test_knowledge_failure_keeps_the_base_result_and_deterministic_report() -> None:
    service = LabService(workflow=RecordingWorkflow(with_knowledge=False))

    run = service.create_run(
        LabRunRequest(
            scenario_kind="custom",
            custom_input="Safe prefix. PRIVATE_CONTINUATION",
        )
    )

    assert run.detection.knowledge_status == "unavailable"
    assert run.detection.knowledge_evidence == ()
    assert run.case_report.evidence_ids == ()
    assert any("知识证据不可用" in item for item in run.case_report.limitations)


def test_failed_creation_does_not_store_a_partial_run_or_private_error() -> None:
    service = LabService(workflow=RecordingWorkflow(fail=True))

    with pytest.raises(LabRunCreationFailed, match="lab_run_failed") as exc_info:
        service.create_run(
            LabRunRequest(
                scenario_kind="custom",
                custom_input="PRIVATE_CUSTOM_INPUT",
            )
        )

    assert service.run_store.snapshot() == ()
    assert "PRIVATE" not in str(exc_info.value)


def test_tool_failure_keeps_a_blocked_run_blocked() -> None:
    service = LabService(workflow=RecordingWorkflow())
    run = service.create_run(
        LabRunRequest(
            scenario_kind="custom",
            custom_input="Safe prefix. PRIVATE_CONTINUATION",
        )
    )

    updated = service.run_tool(
        run.run_id, "gateway_preview", inject_failure=True
    )

    assert updated.tool_results[0].status == "failed"
    assert updated.tool_results[0].effective_action == "block"
    assert updated.detection.decision == "block"
    assert service.get_run(run.run_id) == updated


def test_metrics_aggregate_only_redacted_bounded_run_outcomes() -> None:
    service = LabService(workflow=RecordingWorkflow())
    run = service.create_run(
        LabRunRequest(
            scenario_kind="custom",
            custom_input="Safe prefix. PRIVATE_CONTINUATION",
        )
    )
    service.run_tool(run.run_id, "gateway_preview", inject_failure=False)
    service.run_tool(run.run_id, "soc_case_preview", inject_failure=True)

    metrics = service.metrics()

    assert metrics.model_dump(mode="json") == {
        "run_count": 1,
        "counterfactual_eligible_count": 1,
        "counterfactual_executed_count": 1,
        "counterfactual_execution_rate": 1.0,
        "evidence_agreement_count": 1,
        "evidence_conflict_count": 0,
        "evidence_conflict_rate": 0.0,
        "tool_success_count": 1,
        "tool_failure_count": 1,
        "tool_success_rate": 0.5,
        "report_generated_count": 1,
        "report_fallback_count": 0,
        "action_invariance_count": 1,
        "action_invariance_rate": 1.0,
        "latency_ms": {"p50": 30.0, "p95": 30.0},
        "privacy_violation_count": 0,
    }
    assert_public_payload(metrics)
    serialized = metrics.model_dump_json()
    for forbidden in (
        "sample_id",
        "scenario_id",
        "attack_family",
        "input_hash",
        "agent-ablation-v1",
        "PRIVATE_CONTINUATION",
    ):
        assert forbidden not in serialized
