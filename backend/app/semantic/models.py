from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Protocol

from pydantic import BaseModel, Field, StringConstraints


NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class SemanticSeverity(StrEnum):
    SAFE = "safe"
    CONTROVERSIAL = "controversial"
    UNSAFE = "unsafe"
    UNAVAILABLE = "unavailable"


class SemanticCategory(StrEnum):
    VIOLENT = "violent"
    NON_VIOLENT_ILLEGAL_ACTS = "non_violent_illegal_acts"
    SEXUAL_CONTENT = "sexual_content"
    PII = "pii"
    SUICIDE_SELF_HARM = "suicide_self_harm"
    UNETHICAL_ACTS = "unethical_acts"
    POLITICALLY_SENSITIVE = "politically_sensitive"
    COPYRIGHT_VIOLATION = "copyright_violation"
    JAILBREAK = "jailbreak"


class SemanticAssessment(BaseModel):
    severity: SemanticSeverity
    categories: list[SemanticCategory]
    model_id: NonEmptyText
    model_version: NonEmptyText
    latency_ms: float = Field(ge=0)


class SemanticGuard(Protocol):
    def assess(self, prompt: str) -> SemanticAssessment: ...
