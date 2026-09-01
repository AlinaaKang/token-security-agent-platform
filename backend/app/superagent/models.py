from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.lab.models import LabToolId, assert_public_payload, safer_action
from app.pcap.models import PcapMissionResult
from app.schemas import Decision, NonEmptyText


class SuperAgentObjective(StrEnum):
    INVESTIGATE_AND_RESPOND = "investigate_and_respond"
    TRIAGE_PCAP_EVIDENCE = "triage_pcap_evidence"


class SuperAgentFinalStatus(StrEnum):
    CLOSED_SAFE = "closed_safe"
    CONTAINED = "contained"
    REVIEW_REQUIRED = "review_required"
    DEGRADED = "degraded"


class SuperAgentTracePhase(StrEnum):
    PLAN = "plan"
    ACT = "act"
    OBSERVE = "observe"
    REPLAN = "replan"
    COMPLETE = "complete"


class SuperAgentActor(StrEnum):
    COORDINATOR = "coordinator"
    SEMANTIC_ANALYST = "semantic_analyst"
    TOKEN_ANALYST = "token_analyst"
    KNOWLEDGE_ANALYST = "knowledge_analyst"
    RESPONSE_OPERATOR = "response_operator"


class _FrozenPublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def enforce_public_payload(self) -> _FrozenPublicModel:
        assert_public_payload(self.model_dump(mode="json"))
        return self


class SuperAgentMissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: Literal[
        SuperAgentObjective.INVESTIGATE_AND_RESPOND
    ] = SuperAgentObjective.INVESTIGATE_AND_RESPOND
    scenario_kind: Literal["frozen"] = "frozen"
    sample_id: NonEmptyText
    mode: Literal["analysis", "gateway"] = "analysis"


class PcapTriageMissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: Literal[SuperAgentObjective.TRIAGE_PCAP_EVIDENCE]
    authorization_id: str = Field(pattern=r"^pcap_auth_[0-9a-f]{32}$")


SuperAgentCreateMissionRequest = Annotated[
    SuperAgentMissionRequest | PcapTriageMissionRequest,
    Field(discriminator="objective"),
]


class SuperAgentPlanStep(_FrozenPublicModel):
    sequence: int = Field(ge=1, le=6)
    actor: SuperAgentActor
    action_code: NonEmptyText
    summary: NonEmptyText


class SuperAgentTraceEvent(_FrozenPublicModel):
    sequence: int = Field(ge=1, le=12)
    phase: SuperAgentTracePhase
    actor: SuperAgentActor
    status: Literal["planned", "succeeded", "failed", "skipped"]
    summary: NonEmptyText
    evidence_codes: tuple[NonEmptyText, ...] = ()
    tool_id: LabToolId | None = None


class SuperAgentExecutionReference(_FrozenPublicModel):
    execution_id: NonEmptyText
    tool_id: LabToolId
    status: Literal["succeeded", "failed"]
    source_action: Decision
    effective_action: Decision
    receipt_id: NonEmptyText | None = None
    artifact_id: NonEmptyText | None = None
    evidence_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )

    @model_validator(mode="after")
    def effective_action_must_be_monotonic(
        self,
    ) -> SuperAgentExecutionReference:
        if self.effective_action != safer_action(
            self.source_action, self.effective_action
        ):
            raise ValueError("effective action cannot be weaker than source action")
        return self


class SuperAgentMissionResult(_FrozenPublicModel):
    mission_id: str = Field(pattern=r"^mission_[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^lab_[0-9a-f]{32}$")
    objective: Literal[SuperAgentObjective.INVESTIGATE_AND_RESPOND]
    scenario_id: NonEmptyText
    scenario_label: NonEmptyText
    attack_family: NonEmptyText | None = None
    mode: Literal["analysis", "gateway"]
    base_action: Decision
    final_status: SuperAgentFinalStatus
    initial_plan: tuple[SuperAgentPlanStep, ...] = Field(max_length=6)
    final_plan: tuple[LabToolId, ...] = Field(max_length=3)
    events: tuple[SuperAgentTraceEvent, ...] = Field(max_length=12)
    executions: tuple[SuperAgentExecutionReference, ...] = Field(max_length=3)
    limitations: tuple[NonEmptyText, ...] = Field(min_length=1, max_length=4)
    created_at: NonEmptyText


class SuperAgentCapabilities(_FrozenPublicModel):
    ready: Literal[True] = True
    internal_only: Literal[True] = True
    objectives: tuple[SuperAgentObjective, ...] = (
        SuperAgentObjective.INVESTIGATE_AND_RESPOND,
    )
    actors: tuple[SuperAgentActor, ...] = tuple(SuperAgentActor)
    max_tool_calls: Literal[3] = 3
    max_trace_events: Literal[12] = 12
    replanning_limit: Literal[1] = 1


SuperAgentStoredMission = SuperAgentMissionResult | PcapMissionResult
