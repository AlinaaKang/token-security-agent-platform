"""Deterministic, synthetic-only metrics for localized PCAP detection."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.pcap.detection_models import PcapDetector, PcapLocalizedEvidence


class PcapEvaluationCase(BaseModel):
    """A public test label paired with already-sanitized detector evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label_risky: bool
    expected_start_packet: int | None = Field(default=None, ge=1, strict=True)
    expected_end_packet: int | None = Field(default=None, ge=1, strict=True)
    evidence: tuple[PcapLocalizedEvidence, ...] = ()

    @model_validator(mode="after")
    def validate_interval(self) -> PcapEvaluationCase:
        interval = (self.expected_start_packet, self.expected_end_packet)
        if self.label_risky and any(value is None for value in interval):
            raise ValueError("risky cases require expected packet interval")
        if any(value is not None for value in interval) and (
            self.expected_start_packet is None
            or self.expected_end_packet is None
            or self.expected_start_packet > self.expected_end_packet
        ):
            raise ValueError("expected packet interval must be ordered")
        if not self.label_risky and any(value is not None for value in interval):
            raise ValueError("benign cases must not contain expected packet interval")
        return self


class PcapAblationMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(ge=0, strict=True)
    true_positive: int = Field(ge=0, strict=True)
    false_positive: int = Field(ge=0, strict=True)
    false_negative: int = Field(ge=0, strict=True)
    true_negative: int = Field(ge=0, strict=True)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)
    localization_hit_rate: float = Field(ge=0, le=1)


class PcapDetectionEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(ge=1, strict=True)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)
    localization_hit_rate: float = Field(ge=0, le=1)
    ablations: dict[str, PcapAblationMetrics]


class PcapEvaluationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    benchmark_version: str = Field(min_length=1, max_length=80)
    dataset_kind: Literal["synthetic_sanitized_regression"]
    generated_at: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
    )
    cases: tuple[PcapEvaluationCase, ...] = Field(min_length=1, max_length=500)


class PcapEvaluationSummary(PcapDetectionEvaluation):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    benchmark_version: str = Field(min_length=1, max_length=80)
    dataset_kind: Literal["synthetic_sanitized_regression"]
    generated_at: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
    )


_FORBIDDEN_MANIFEST_FIELDS = frozenset(
    {
        "body", "filename", "hash", "header", "ip", "ip_address", "mac",
        "path", "payload", "port", "prompt", "request_body", "sha256",
        "stderr", "token_text", "uri",
    }
)


def _validate_sanitized_manifest(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in _FORBIDDEN_MANIFEST_FIELDS:
                raise ValueError(f"forbidden field in PCAP evaluation manifest: {normalized}")
            _validate_sanitized_manifest(child)
    elif isinstance(value, list):
        for child in value:
            _validate_sanitized_manifest(child)


def load_pcap_evaluation(path: Path) -> PcapEvaluationSummary:
    raw = json.loads(path.read_text(encoding="ascii"))
    _validate_sanitized_manifest(raw)
    manifest = PcapEvaluationManifest.model_validate(raw)
    result = evaluate_pcap_detection(manifest.cases)
    return PcapEvaluationSummary(
        schema_version=manifest.schema_version,
        benchmark_version=manifest.benchmark_version,
        dataset_kind=manifest.dataset_kind,
        generated_at=manifest.generated_at,
        **result.model_dump(),
    )


def evaluate_pcap_detection(cases: Sequence[PcapEvaluationCase]) -> PcapDetectionEvaluation:
    """Evaluate aggregate alerting and interval localization without private data."""
    if not cases:
        raise ValueError("evaluation cases must not be empty")
    ablations = {
        "rule_only": _evaluate(cases, lambda item: item.detector is PcapDetector.HTTP_RULE),
        "behavior_only": _evaluate(cases, lambda item: item.detector is not PcapDetector.HTTP_RULE),
        "fused": _evaluate(cases, lambda item: True),
    }
    fused = ablations["fused"]
    return PcapDetectionEvaluation(
        sample_count=fused.sample_count,
        precision=fused.precision,
        recall=fused.recall,
        f1=fused.f1,
        false_positive_rate=fused.false_positive_rate,
        localization_hit_rate=fused.localization_hit_rate,
        ablations=ablations,
    )


def _evaluate(
    cases: Sequence[PcapEvaluationCase], include: callable,
) -> PcapAblationMetrics:
    predictions: list[bool] = []
    hits: list[bool] = []
    for case in cases:
        selected = tuple(item for item in case.evidence if include(item))
        predictions.append(bool(selected))
        if case.label_risky and case.expected_start_packet is not None:
            start, end = case.expected_start_packet, case.expected_end_packet
            hits.append(any(item.start_packet <= end and item.end_packet >= start for item in selected))
    tp = sum(pred and case.label_risky for pred, case in zip(predictions, cases, strict=True))
    fp = sum(pred and not case.label_risky for pred, case in zip(predictions, cases, strict=True))
    fn = sum(not pred and case.label_risky for pred, case in zip(predictions, cases, strict=True))
    tn = sum(not pred and not case.label_risky for pred, case in zip(predictions, cases, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    localization = sum(hits) / sum(case.label_risky for case in cases)
    return PcapAblationMetrics(
        sample_count=len(cases), true_positive=tp, false_positive=fp,
        false_negative=fn, true_negative=tn, precision=precision, recall=recall,
        f1=f1, false_positive_rate=fpr, localization_hit_rate=localization,
    )
