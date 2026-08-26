from __future__ import annotations

from app.semantic.models import (
    SemanticAssessment,
    SemanticCategory,
    SemanticSeverity,
)


class SemanticOutputError(ValueError):
    """Raised when generated Guard output violates the trusted contract."""


_SEVERITIES = {
    "Safe": SemanticSeverity.SAFE,
    "Controversial": SemanticSeverity.CONTROVERSIAL,
    "Unsafe": SemanticSeverity.UNSAFE,
}

_CATEGORIES = {
    "Violent": SemanticCategory.VIOLENT,
    "Non-violent Illegal Acts": SemanticCategory.NON_VIOLENT_ILLEGAL_ACTS,
    "Sexual Content or Sexual Acts": SemanticCategory.SEXUAL_CONTENT,
    "PII": SemanticCategory.PII,
    "Suicide & Self-Harm": SemanticCategory.SUICIDE_SELF_HARM,
    "Unethical Acts": SemanticCategory.UNETHICAL_ACTS,
    "Politically Sensitive Topics": SemanticCategory.POLITICALLY_SENSITIVE,
    "Copyright Violation": SemanticCategory.COPYRIGHT_VIOLATION,
    "Jailbreak": SemanticCategory.JAILBREAK,
}


def parse_guard_output(
    raw: str,
    *,
    model_id: str,
    model_version: str,
    latency_ms: float,
) -> SemanticAssessment:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 2:
        raise SemanticOutputError("semantic Guard output must contain two lines")

    safety_prefix = "Safety:"
    categories_prefix = "Categories:"
    if not lines[0].startswith(safety_prefix) or not lines[1].startswith(
        categories_prefix
    ):
        raise SemanticOutputError("semantic Guard output has invalid fields")

    safety_label = lines[0][len(safety_prefix) :].strip()
    severity = _SEVERITIES.get(safety_label)
    if severity is None:
        raise SemanticOutputError("semantic Guard output has unknown severity")

    categories_text = lines[1][len(categories_prefix) :].strip()
    if severity is SemanticSeverity.SAFE:
        if categories_text != "None":
            raise SemanticOutputError("safe semantic output must have no categories")
        categories: list[SemanticCategory] = []
    else:
        if not categories_text or categories_text == "None":
            raise SemanticOutputError("risky semantic output must include categories")
        categories = []
        for label in (item.strip() for item in categories_text.split(",")):
            category = _CATEGORIES.get(label)
            if category is None:
                raise SemanticOutputError("semantic Guard output has unknown category")
            if category not in categories:
                categories.append(category)

    return SemanticAssessment(
        severity=severity,
        categories=categories,
        model_id=model_id,
        model_version=model_version,
        latency_ms=latency_ms,
    )
