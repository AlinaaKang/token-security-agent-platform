from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent.fusion import FusionReason
from app.knowledge.models import (
    KnowledgeEvidence,
    KnowledgeId,
    KnowledgeStatus,
    ReportStatus,
)
from app.schemas import (
    AnalysisResult,
    Decision,
    MAX_PROMPT_CHARACTERS,
    NonEmptyText,
    Provenance,
    TokenSignal,
)
from app.semantic.models import SemanticCategory, SemanticSeverity


FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "prompt",
        "suffix",
        "token_text",
        "token_id",
        "query_text",
        "raw_output",
        "guard_raw_output",
    }
)


class LabToolId(StrEnum):
    GATEWAY_ENFORCEMENT = "gateway_enforcement"
    SECURITY_CASE = "security_case"
    EVIDENCE_BUNDLE = "evidence_bundle"

    # Compatibility aliases keep the current preview-only dry run importable
    # until its API migration explicitly adopts the persistent tools.
    GATEWAY_PREVIEW = GATEWAY_ENFORCEMENT
    SOC_CASE_PREVIEW = SECURITY_CASE
    EVIDENCE_EXPORT_PREVIEW = EVIDENCE_BUNDLE

    @classmethod
    def _missing_(cls, value: object) -> LabToolId | None:
        legacy_values = {
            "gateway_preview": cls.GATEWAY_ENFORCEMENT,
            "soc_case_preview": cls.SECURITY_CASE,
            "evidence_export_preview": cls.EVIDENCE_BUNDLE,
        }
        return legacy_values.get(value) if isinstance(value, str) else None


class LabToolPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: LabToolId
    title: NonEmptyText
    status: Literal["planned"] = "planned"
    effective_action: Decision
    artifact_summary: NonEmptyText
    knowledge_ids: tuple[KnowledgeId, ...] = ()


class ToolDryRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: LabToolId
    status: Literal["succeeded", "failed"]
    error_code: Literal["simulated_tool_failure"] | None = None
    latency_ms: float = Field(ge=0)
    effective_action: Decision
    artifact_summary: NonEmptyText
    evidence_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )


class LabRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_kind: Literal["custom", "frozen"]
    custom_input: str | None = Field(default=None, max_length=MAX_PROMPT_CHARACTERS)
    sample_id: NonEmptyText | None = None
    mode: Literal["analysis", "gateway"] = "analysis"

    @model_validator(mode="after")
    def validate_input_source(self) -> LabRunRequest:
        has_custom = self.custom_input is not None and bool(self.custom_input.strip())
        has_sample = self.sample_id is not None
        if self.scenario_kind == "custom" and has_custom and not has_sample:
            return self
        if self.scenario_kind == "frozen" and has_sample and self.custom_input is None:
            return self
        raise ValueError("scenario kind must match exactly one input source")


class LabScenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: NonEmptyText
    label: NonEmptyText
    scenario_kind: Literal["synthetic", "protected"]
    attack_family: NonEmptyText | None = None
    ready: bool = True


class LabStage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stage_id: Literal[
        "semantic_guard",
        "token_observation",
        "entropy_cpd",
        "fixed_fusion",
        "knowledge_retrieval",
    ]
    status: Literal["succeeded", "unavailable"]
    latency_ms: float | None = Field(default=None, ge=0)
    timing_basis: Literal["measured", "combined", "unavailable"]
    summary: NonEmptyText


class ToolDryRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    inject_failure: bool = False


class LabPublicSignal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int = Field(ge=0)
    entropy: float = Field(ge=0)
    nll: float = Field(ge=0)
    cpd_entropy: float = Field(ge=0)
    cpd_nll: float = Field(ge=0)
    risk: float = Field(ge=0, le=1)

    @classmethod
    def from_token_signal(cls, signal: TokenSignal) -> LabPublicSignal:
        return cls(
            index=signal.index,
            entropy=signal.entropy,
            nll=signal.nll,
            cpd_entropy=signal.cpd_entropy,
            cpd_nll=signal.cpd_nll,
            risk=signal.risk,
        )


class LabDetectionSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    risk_score: float = Field(ge=0, le=1)
    detector_score: float = Field(ge=0)
    detector_status: NonEmptyText
    semantic_severity: SemanticSeverity
    semantic_categories: tuple[SemanticCategory, ...] = ()
    semantic_model_id: NonEmptyText
    semantic_model_version: NonEmptyText
    semantic_latency_ms: float = Field(ge=0)
    fusion_reason: FusionReason
    suspicious_span: dict[str, int] | None = None
    signals: tuple[LabPublicSignal, ...]
    provenance: Provenance
    latency_ms: float = Field(ge=0)
    knowledge_status: KnowledgeStatus
    knowledge_snapshot_version: NonEmptyText | None = None
    knowledge_latency_ms: float = Field(ge=0)
    knowledge_evidence: tuple[KnowledgeEvidence, ...] = ()
    report_status: ReportStatus

    @classmethod
    def from_analysis(cls, result: AnalysisResult) -> LabDetectionSnapshot:
        return cls(
            decision=result.decision,
            risk_score=result.risk_score,
            detector_score=result.detector_score,
            detector_status=result.detector_status,
            semantic_severity=result.semantic_severity,
            semantic_categories=tuple(result.semantic_categories),
            semantic_model_id=result.semantic_model_id,
            semantic_model_version=result.semantic_model_version,
            semantic_latency_ms=result.semantic_latency_ms,
            fusion_reason=result.fusion_reason,
            suspicious_span=(
                result.suspicious_span.model_dump(mode="json")
                if result.suspicious_span is not None
                else None
            ),
            signals=tuple(
                LabPublicSignal.from_token_signal(signal)
                for signal in result.signals
            ),
            provenance=result.provenance,
            latency_ms=result.latency_ms,
            knowledge_status=result.knowledge_status,
            knowledge_snapshot_version=result.knowledge_snapshot_version,
            knowledge_latency_ms=result.knowledge_latency_ms,
            knowledge_evidence=tuple(result.knowledge_evidence),
            report_status=result.report_status,
        )


class CounterfactualSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    semantic_severity: NonEmptyText
    detector_status: NonEmptyText
    risk_score: float = Field(ge=0, le=1)
    detector_score: float = Field(ge=0)
    decision: Decision
    latency_ms: float = Field(ge=0)


class CounterfactualResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    interpretation: Literal["risk_reduced", "unchanged", "inconclusive"]
    reason: Literal[
        "completed",
        "no_predicted_onset",
        "invalid_predicted_onset",
        "provenance_mismatch",
        "recheck_failed",
    ]
    char_start: int | None = Field(default=None, ge=0)
    calibration_version: NonEmptyText
    original: CounterfactualSnapshot
    rechecked: CounterfactualSnapshot | None = None
    risk_score_delta: float | None = None
    detector_score_delta: float | None = None
    action_changed: bool = False


class LabCaseReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_status: Literal["deterministic", "fallback"]
    summary: NonEmptyText
    evidence_ids: tuple[KnowledgeId, ...] = ()
    handling_steps: tuple[NonEmptyText, ...]
    limitations: tuple[NonEmptyText, ...]
    tool_statuses: dict[LabToolId, Literal["succeeded", "failed"]] = Field(
        default_factory=dict
    )


class LabRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: NonEmptyText
    status: Literal["completed"] = "completed"
    scenario_id: NonEmptyText
    scenario_kind: Literal["custom", "synthetic", "protected"]
    scenario_label: NonEmptyText
    attack_family: NonEmptyText | None = None
    mode: Literal["analysis", "gateway"]
    created_at: str
    stages: tuple[LabStage, ...]
    detection: LabDetectionSnapshot
    counterfactual: CounterfactualResult
    tool_plans: tuple[LabToolPlan, ...]
    tool_results: tuple[ToolDryRunResult, ...] = ()
    case_report: LabCaseReport


class LabLatencySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    p50: float = Field(ge=0)
    p95: float = Field(ge=0)


class LabMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_count: int = Field(ge=0)
    counterfactual_eligible_count: int = Field(ge=0)
    counterfactual_executed_count: int = Field(ge=0)
    counterfactual_execution_rate: float = Field(ge=0, le=1)
    evidence_agreement_count: int = Field(ge=0)
    evidence_conflict_count: int = Field(ge=0)
    evidence_conflict_rate: float = Field(ge=0, le=1)
    tool_success_count: int = Field(ge=0)
    tool_failure_count: int = Field(ge=0)
    tool_success_rate: float = Field(ge=0, le=1)
    report_generated_count: int = Field(ge=0)
    report_fallback_count: int = Field(ge=0)
    action_invariance_count: int = Field(ge=0)
    action_invariance_rate: float = Field(ge=0, le=1)
    latency_ms: LabLatencySummary
    privacy_violation_count: int = Field(ge=0)


def assert_public_payload(payload: Any) -> None:
    if isinstance(payload, BaseModel):
        assert_public_payload(payload.model_dump(mode="json"))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in FORBIDDEN_PUBLIC_KEYS:
                raise ValueError(f"lab payload contains forbidden field: {key}")
            assert_public_payload(value)
        return
    if isinstance(payload, (list, tuple)):
        for value in payload:
            assert_public_payload(value)


_ACTION_RANK = {
    Decision.ALLOW: 0,
    Decision.REVIEW: 1,
    Decision.SANITIZE_RECHECK: 2,
    Decision.BLOCK: 3,
}


def safer_action(
    original: Decision | str, proposed: Decision | str
) -> Decision:
    original_action = Decision(original)
    proposed_action = Decision(proposed)
    if _ACTION_RANK[proposed_action] > _ACTION_RANK[original_action]:
        return proposed_action
    return original_action
