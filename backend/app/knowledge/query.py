from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from app.agent.fusion import FusionReason, Mode
from app.schemas import Decision, DetectorStatus
from app.semantic.models import SemanticCategory, SemanticSeverity


class SafeQueryError(ValueError):
    """Raised without input details when a retrieval query cannot be built."""


class RetrievalMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    semantic_severity: SemanticSeverity
    semantic_categories: tuple[SemanticCategory, ...] = ()
    detector_status: DetectorStatus
    fusion_reason: FusionReason
    decision: Decision
    mode: Mode
    attack_family: str | None = None


class RetrievalQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    query_text: str = Field(repr=False, exclude=True)
    lexical_terms: tuple[str, ...]
    routing_tags: tuple[str, ...]
    used_prefix_only: bool


_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----",
    flags=re.IGNORECASE | re.DOTALL,
)
_PEM_MARKER = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----|-----END [A-Z0-9 ]+-----",
    flags=re.IGNORECASE,
)
_TOKEN_ASSIGNMENT = re.compile(
    r"\b(?:api[_-]?key|access[_-]?token|token|secret|password)\s*[:=]\s*"
    r"[\"']?[^\s\"',;]+",
    flags=re.IGNORECASE,
)
_BEARER = re.compile(
    r"\bbearer\s+[A-Z0-9._~+/=-]{6,}",
    flags=re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
_IPV4 = re.compile(
    r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"
)
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)
_LONG_DIGITS = re.compile(r"(?<!\d)\d{8,}(?!\d)")
_LATIN_TERM = re.compile(r"[a-z][a-z0-9_.-]{1,63}")
_CJK_RUN = re.compile(r"[\u3400-\u9fff]+")


def _ordered_unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _redact(text: str) -> str:
    value = _PEM_BLOCK.sub(" redacted ", text)
    for pattern in (
        _PEM_MARKER,
        _TOKEN_ASSIGNMENT,
        _BEARER,
        _EMAIL,
        _IPV4,
        _IPV6,
        _LONG_DIGITS,
    ):
        value = pattern.sub(" redacted ", value)
    return value


def lexical_terms(text: str) -> tuple[str, ...]:
    terms = _LATIN_TERM.findall(text)
    for run in _CJK_RUN.findall(text):
        if len(run) == 1:
            terms.append(run)
        else:
            terms.extend(run[index : index + 2] for index in range(len(run) - 1))
    return _ordered_unique(terms)


def _routing_tags(metadata: RetrievalMetadata) -> tuple[str, ...]:
    values = [
        metadata.semantic_severity.value,
        *(category.value for category in metadata.semantic_categories),
        metadata.detector_status,
        metadata.fusion_reason.value,
        metadata.decision.value,
        metadata.mode,
    ]
    if metadata.attack_family:
        values.append(metadata.attack_family.strip().casefold())
    return _ordered_unique(values)


class SafeQueryBuilder:
    def __init__(self, max_characters: int = 2048) -> None:
        if max_characters < 1:
            raise ValueError("max_characters must be positive")
        self._max_characters = max_characters

    def build(
        self,
        prompt: str,
        *,
        char_onset: int | None,
        metadata: RetrievalMetadata,
    ) -> RetrievalQuery:
        if not prompt.strip():
            raise SafeQueryError("invalid safe query input")

        used_prefix_only = bool(
            char_onset is not None and 0 < char_onset < len(prompt)
        )
        bounded = prompt[:char_onset] if used_prefix_only else prompt
        bounded = bounded[: self._max_characters]
        sanitized = " ".join(_redact(bounded).split()).casefold()
        if not sanitized:
            sanitized = "redacted"
        return RetrievalQuery(
            query_text=sanitized,
            lexical_terms=lexical_terms(sanitized),
            routing_tags=_routing_tags(metadata),
            used_prefix_only=used_prefix_only,
        )
