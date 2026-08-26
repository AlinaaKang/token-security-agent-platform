from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
)

from app.agent.fusion import FusionReason
from app.semantic.models import SemanticCategory, SemanticSeverity


NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256Text = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
]
KnowledgeId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=96),
]


class KnowledgePublisher(StrEnum):
    OWASP = "owasp"
    MITRE = "mitre"
    NIST = "nist"


class RiskDomain(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SENSITIVE_INFORMATION = "sensitive_information"
    EXCESSIVE_AGENCY = "excessive_agency"
    GOVERNANCE = "governance"
    INCIDENT_RESPONSE = "incident_response"


class KnowledgeMode(StrEnum):
    OFF = "off"
    EVIDENCE = "evidence"
    REPORT = "report"


class KnowledgeStatus(StrEnum):
    OFF = "off"
    READY = "ready"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"


class ReportStatus(StrEnum):
    OFF = "off"
    GENERATED = "generated"
    FALLBACK = "fallback"
    UNAVAILABLE = "unavailable"


class KnowledgeSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    publisher: KnowledgePublisher
    title: NonEmptyText
    url: NonEmptyText
    version: NonEmptyText
    verified_at: datetime
    usage_note: NonEmptyText

    @field_validator("url")
    @classmethod
    def validate_official_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("knowledge source must use approved HTTPS origin")
        return value

    @field_validator("url")
    @classmethod
    def url_must_have_allowlisted_host(cls, value: str, info: ValidationInfo) -> str:
        from urllib.parse import urlsplit

        publisher = info.data.get("publisher")
        allowed = {
            KnowledgePublisher.OWASP: {"genai.owasp.org"},
            KnowledgePublisher.MITRE: {"atlas.mitre.org"},
            KnowledgePublisher.NIST: {"nist.gov", "www.nist.gov"},
        }
        if urlsplit(value).hostname not in allowed.get(publisher, set()):
            raise ValueError("knowledge source host is not approved")
        return value


class KnowledgeCard(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    knowledge_id: KnowledgeId
    title_zh: NonEmptyText
    risk_domain: RiskDomain
    semantic_categories: tuple[SemanticCategory, ...] = ()
    detector_tags: tuple[NonEmptyText, ...]
    fusion_tags: tuple[FusionReason, ...] = ()
    attack_families: tuple[NonEmptyText, ...] = ()
    summary: NonEmptyText
    indicators: tuple[NonEmptyText, ...] = Field(min_length=1)
    recommendations: tuple[NonEmptyText, ...] = Field(min_length=1)
    retrieval_tags: tuple[NonEmptyText, ...] = Field(min_length=1)
    source: KnowledgeSource
    content_sha256: Sha256Text

    @field_validator(
        "semantic_categories",
        "detector_tags",
        "fusion_tags",
        "attack_families",
        "indicators",
        "recommendations",
        "retrieval_tags",
    )
    @classmethod
    def values_must_be_unique(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        normalized = [str(item).casefold() for item in value]
        if len(normalized) != len(set(normalized)):
            raise ValueError("knowledge card list values must be unique")
        return value


class KnowledgeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, le=1)
    snapshot_version: NonEmptyText
    card_count: int = Field(ge=1)
    cards_sha256: Sha256Text
    publishers: tuple[KnowledgePublisher, ...] = Field(min_length=1)


class KnowledgeSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: KnowledgeManifest
    cards: tuple[KnowledgeCard, ...] = Field(min_length=1)


class KnowledgeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    knowledge_id: KnowledgeId
    title_zh: NonEmptyText
    risk_domain: RiskDomain
    summary: NonEmptyText
    recommendations: tuple[NonEmptyText, ...]
    source: KnowledgeSource
    retrieval_score: float = Field(ge=0)
    matched_tags: tuple[NonEmptyText, ...] = ()


class NormalizedSecurityFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    semantic_severity: SemanticSeverity
    semantic_categories: tuple[SemanticCategory, ...]
    detector_status: NonEmptyText
    anomaly_char_start: int | None = Field(default=None, ge=0)
    fusion_reason: FusionReason
    decision: NonEmptyText
    mode: NonEmptyText
    attack_family: NonEmptyText | None = None
