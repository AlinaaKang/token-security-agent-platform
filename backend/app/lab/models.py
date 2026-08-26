from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas import Decision, MAX_PROMPT_CHARACTERS, NonEmptyText, TokenSignal


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
    GATEWAY_PREVIEW = "gateway_preview"
    SOC_CASE_PREVIEW = "soc_case_preview"
    EVIDENCE_EXPORT_PREVIEW = "evidence_export_preview"


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
