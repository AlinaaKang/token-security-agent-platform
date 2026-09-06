from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.lab.models import assert_public_payload
from app.schemas import MAX_PROMPT_CHARACTERS, NonEmptyText


_AGENT_PRIVATE_KEYS = frozenset(
    {
        "prompt",
        "suffix",
        "payload",
        "file_path",
        "file_identity",
        "token_id",
        "token_ids",
        "token_text",
        "query_text",
        "raw_output",
        "guard_raw_output",
        "hidden_reasoning",
        "system_prompt",
        "scratchpad",
        "credential",
        "authorization_secret",
    }
)


def _assert_agent_public_payload(payload: Any) -> None:
    if isinstance(payload, BaseModel):
        _assert_agent_public_payload(payload.model_dump(mode="json"))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in _AGENT_PRIVATE_KEYS:
                raise ValueError(f"forbidden public field: {key}")
            _assert_agent_public_payload(value)
        return
    if isinstance(payload, (list, tuple)):
        for value in payload:
            _assert_agent_public_payload(value)


class _PublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_public_payload(self) -> _PublicModel:
        payload = self.model_dump(mode="json")
        assert_public_payload(payload)
        _assert_agent_public_payload(payload)
        return self


class EvidenceAuthenticity(StrEnum):
    REAL = "real"
    SIMULATED = "simulated"
    DERIVED = "derived"


class AgentTaskType(StrEnum):
    KNOWLEDGE_EXPLANATION = "knowledge_explanation"
    PROMPT_INVESTIGATION = "prompt_investigation"
    PCAP_DATASET_INVESTIGATION = "pcap_dataset_investigation"
    PCAP_CAPTURE_INVESTIGATION = "pcap_capture_investigation"
    CROSS_DOMAIN_CASE = "cross_domain_case"
    REPORT_GENERATION = "report_generation"


class AgentTaskStatus(StrEnum):
    DRAFT = "draft"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    PLANNED = "planned"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentIntent(_PublicModel):
    kind: Literal[
        "identity",
        "smalltalk",
        "capabilities",
        "explain_attack",
        "explain_pcap",
        "explain_current_evidence",
        "investigate_prompt",
        "investigate_pcap_dataset",
        "investigate_pcap_capture",
        "run_cross_domain_demo",
        "continue_task",
        "generate_report",
        "cancel_task",
        "clarify",
        "out_of_scope",
    ]
    task_type: AgentTaskType | None = None
    objective_summary: NonEmptyText
    requires_task: bool = False
    requires_authorization: bool = False
    control_is_explicit: bool = False


class AgentPlanStep(_PublicModel):
    step_id: str = Field(pattern=r"^step_[0-9]{2}$")
    tool_id: NonEmptyText | None = None
    status: Literal["waiting", "running", "succeeded", "failed", "skipped"]
    requires_authorization: bool = False
    summary: NonEmptyText
    depends_on: tuple[str, ...] = Field(default=(), max_length=12)
    attempt: int = Field(default=0, ge=0, le=3)


class AgentObservation(_PublicModel):
    observation_id: NonEmptyText
    kind: NonEmptyText
    status: Literal["succeeded", "failed", "unavailable", "degraded"]
    summary: NonEmptyText
    observed_at: NonEmptyText
    tool_id: NonEmptyText | None = None
    evidence_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=200)
    retryable: bool = False
    public_error_code: NonEmptyText | None = None


class AgentEvidence(_PublicModel):
    evidence_id: NonEmptyText
    authenticity: EvidenceAuthenticity
    source_type: NonEmptyText
    source_ref: NonEmptyText
    tool_id: NonEmptyText | None = None
    summary: NonEmptyText
    observed_at: NonEmptyText
    uncertainty: NonEmptyText
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentConfidenceChange(_PublicModel):
    before: float = Field(ge=0, le=1)
    after: float = Field(ge=0, le=1)
    evidence_refs: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=200)
    reason: NonEmptyText
    changed_at: NonEmptyText


class AgentHypothesis(_PublicModel):
    hypothesis_id: NonEmptyText
    title: NonEmptyText
    status: Literal["investigating", "supported", "weakened", "rejected", "inconclusive"]
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=200)
    opposing_evidence_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=200)
    confidence_changes: tuple[AgentConfidenceChange, ...] = Field(default=(), max_length=50)
    limitations: tuple[NonEmptyText, ...] = Field(default=(), max_length=20)


class AgentTimelineEvent(_PublicModel):
    timeline_id: NonEmptyText
    occurred_at: NonEmptyText
    source_type: NonEmptyText
    authenticity: EvidenceAuthenticity
    summary: NonEmptyText
    evidence_refs: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=200)


class AgentEvidenceConflict(_PublicModel):
    conflict_id: NonEmptyText
    summary: NonEmptyText
    evidence_refs: tuple[NonEmptyText, ...] = Field(min_length=2, max_length=20)
    resolution: NonEmptyText | None = None
    status: Literal["open", "resolved"] = "open"


class AgentMessage(_PublicModel):
    message_id: NonEmptyText
    role: Literal["user", "agent", "system"]
    kind: Literal["message", "status", "question", "result", "warning"] = "message"
    content: str = Field(min_length=1, max_length=MAX_PROMPT_CHARACTERS)
    created_at: NonEmptyText
    evidence_scope: Literal["general", "current_case", "none"] = "none"
    evidence_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=200)


class AgentReportMetadata(_PublicModel):
    report_id: NonEmptyText
    title: NonEmptyText
    format: Literal["markdown"] = "markdown"
    status: Literal["ready", "degraded", "unavailable"]
    artifact_ref: NonEmptyText | None = None
    evidence_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=200)
    generated_at: NonEmptyText


class AgentEvent(_PublicModel):
    task_id: NonEmptyText
    sequence: int = Field(ge=1)
    phase: Literal[
        "understand",
        "plan",
        "authorize",
        "act",
        "observe",
        "replan",
        "verify",
        "complete",
    ]
    kind: NonEmptyText
    summary: NonEmptyText
    created_at: NonEmptyText
    evidence_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=200)


class AgentTaskSnapshot(_PublicModel):
    task_id: NonEmptyText
    version: int = Field(ge=1)
    task_type: AgentTaskType
    status: AgentTaskStatus
    title: NonEmptyText
    objective_summary: NonEmptyText
    created_at: NonEmptyText
    updated_at: NonEmptyText
    messages: tuple[AgentMessage, ...] = Field(default=(), max_length=100)
    plan: tuple[AgentPlanStep, ...] = Field(default=(), max_length=12)
    observations: tuple[AgentObservation, ...] = Field(default=(), max_length=200)
    evidence: tuple[AgentEvidence, ...] = Field(default=(), max_length=200)
    hypotheses: tuple[AgentHypothesis, ...] = Field(default=(), max_length=5)
    timeline: tuple[AgentTimelineEvent, ...] = Field(default=(), max_length=200)
    conflicts: tuple[AgentEvidenceConflict, ...] = Field(default=(), max_length=50)
    events: tuple[AgentEvent, ...] = Field(default=(), max_length=500)
    replan_count: int = Field(default=0, ge=0, le=2)
    authorization_scopes: tuple[NonEmptyText, ...] = Field(default=(), max_length=20)
    final_status: Literal["safe", "risk_found", "contained", "inconclusive"] | None = None
    report: AgentReportMetadata | None = None
    limitations: tuple[NonEmptyText, ...] = Field(default=(), max_length=50)


class AgentCapabilities(_PublicModel):
    planner_mode: Literal["model", "deterministic_fallback", "unavailable"]
    tool_ids: tuple[NonEmptyText, ...] = Field(default=(), max_length=64)
    connector_states: dict[NonEmptyText, Literal["available", "simulated", "degraded", "unavailable"]]
    max_plan_steps: int = Field(default=12, ge=1, le=12)
    max_concurrent_tools: int = Field(default=3, ge=1, le=3)
    max_replans: int = Field(default=2, ge=0, le=2)
    max_active_hypotheses: int = Field(default=5, ge=1, le=5)
    pcap_batch_size: int = Field(default=20, ge=1, le=20)


class AgentCommandRequest(_PublicModel):
    message: str = Field(min_length=1, max_length=MAX_PROMPT_CHARACTERS)
    task_id: NonEmptyText | None = None
    data_source_refs: tuple[NonEmptyText, ...] = Field(default=(), max_length=20)
