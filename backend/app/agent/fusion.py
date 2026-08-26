from __future__ import annotations

from enum import StrEnum
from typing import Literal

from app.agent.policy import Action
from app.semantic.models import SemanticSeverity


Mode = Literal["analysis", "gateway"]


class FusionReason(StrEnum):
    SEMANTIC_UNSAFE = "semantic_unsafe"
    SEMANTIC_CONTROVERSIAL = "semantic_controversial"
    CPD_CANDIDATE = "cpd_candidate"
    ALL_CLEAR = "all_clear"
    SEMANTIC_UNAVAILABLE_CPD_CANDIDATE = (
        "semantic_unavailable_cpd_candidate"
    )
    SEMANTIC_UNAVAILABLE_GATEWAY_FAIL_SAFE = (
        "semantic_unavailable_gateway_fail_safe"
    )
    SEMANTIC_UNAVAILABLE_ANALYSIS_DEGRADED = (
        "semantic_unavailable_analysis_degraded"
    )


class EvidenceFusionPolicy:
    def decide(
        self,
        *,
        mode: Mode,
        semantic: SemanticSeverity,
        cpd_alarm: bool,
    ) -> tuple[Action, FusionReason]:
        if mode not in ("analysis", "gateway"):
            raise ValueError("unsupported analysis mode")

        if semantic is SemanticSeverity.UNSAFE:
            return Action.BLOCK, FusionReason.SEMANTIC_UNSAFE

        if semantic is SemanticSeverity.CONTROVERSIAL:
            return Action.REVIEW, FusionReason.SEMANTIC_CONTROVERSIAL

        if semantic is SemanticSeverity.SAFE:
            if cpd_alarm:
                action = Action.BLOCK if mode == "analysis" else Action.REVIEW
                return action, FusionReason.CPD_CANDIDATE
            return Action.ALLOW, FusionReason.ALL_CLEAR

        if cpd_alarm:
            action = Action.BLOCK if mode == "analysis" else Action.REVIEW
            return action, FusionReason.SEMANTIC_UNAVAILABLE_CPD_CANDIDATE
        if mode == "gateway":
            return (
                Action.REVIEW,
                FusionReason.SEMANTIC_UNAVAILABLE_GATEWAY_FAIL_SAFE,
            )
        return (
            Action.ALLOW,
            FusionReason.SEMANTIC_UNAVAILABLE_ANALYSIS_DEGRADED,
        )
