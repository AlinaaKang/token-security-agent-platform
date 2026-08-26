from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"
    SANITIZE_RECHECK = "sanitize_recheck"


@dataclass(frozen=True)
class BasicPolicy:
    review_threshold: float
    block_threshold: float

    def __post_init__(self) -> None:
        if not 0 <= self.review_threshold < self.block_threshold <= 1:
            raise ValueError(
                "thresholds must satisfy 0 <= review_threshold < block_threshold <= 1"
            )

    def decide(self, risk_score: float) -> Action:
        if not 0 <= risk_score <= 1:
            raise ValueError("risk_score must be between 0 and 1")
        if risk_score >= self.block_threshold:
            return Action.BLOCK
        if risk_score >= self.review_threshold:
            return Action.REVIEW
        return Action.ALLOW
