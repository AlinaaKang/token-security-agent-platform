from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas import NonEmptyText
from app.evaluation.knowledge import KnowledgeEvaluationReport


FORBIDDEN_REPORT_FIELDS = {
    "full_prompt",
    "prompt",
    "request_body",
    "signals",
    "suffix",
    "suffix_text",
    "token_text",
}
EXPECTED_METHODS = {"global_nll", "window_nll", "entropy_cpd"}
EXPECTED_OPERATING_POINTS = {"f1_selected", "low_fpr_selected_on_dev"}


class UnsafeReportError(ValueError):
    pass


class BenchmarkCounts(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(gt=0)
    attacks: int = Field(ge=0)
    benign: int = Field(ge=0)

    @model_validator(mode="after")
    def counts_must_sum(self) -> BenchmarkCounts:
        if self.attacks + self.benign != self.total:
            raise ValueError("attack and benign counts must sum to total")
        return self


class OperatingPoint(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    threshold: float = Field(gt=0, allow_inf_nan=False)
    precision: float = Field(ge=0, le=1, allow_inf_nan=False)
    recall: float = Field(ge=0, le=1, allow_inf_nan=False)
    f1: float = Field(ge=0, le=1, allow_inf_nan=False)
    auroc: float = Field(ge=0, le=1, allow_inf_nan=False)
    false_positive_rate: float = Field(ge=0, le=1, allow_inf_nan=False)


class FamilyOperatingPoint(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    detected: int = Field(ge=0)
    missed: int = Field(ge=0)
    recall: float = Field(ge=0, le=1, allow_inf_nan=False)


class ScoreRange(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    min: float = Field(ge=0, allow_inf_nan=False)
    median: float = Field(ge=0, allow_inf_nan=False)
    max: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def scores_must_be_ordered(self) -> ScoreRange:
        if not self.min <= self.median <= self.max:
            raise ValueError("score range must be ordered")
        return self


class FamilySummary(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    count: int = Field(gt=0)
    operating_points: dict[str, FamilyOperatingPoint]
    score: ScoreRange

    @model_validator(mode="after")
    def validate_family(self) -> FamilySummary:
        if set(self.operating_points) != EXPECTED_OPERATING_POINTS:
            raise ValueError("family must contain both operating points")
        for point in self.operating_points.values():
            if point.detected + point.missed != self.count:
                raise ValueError("family detections must sum to count")
        return self


class LocalizationSummary(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    onset_mae: float = Field(ge=0, allow_inf_nan=False)
    trigger_in_suffix_rate: float = Field(ge=0, le=1, allow_inf_nan=False)


class LatencySummary(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    p50_ms: float = Field(ge=0, allow_inf_nan=False)
    p95_ms: float = Field(ge=0, allow_inf_nan=False)


class MethodSummary(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    display_name: NonEmptyText
    profile: dict[str, str | int | float | None]
    operating_points: dict[str, OperatingPoint]
    families: dict[str, FamilySummary]
    localization: LocalizationSummary | None
    latency_ms: LatencySummary

    @model_validator(mode="after")
    def method_must_contain_both_operating_points(self) -> MethodSummary:
        if set(self.operating_points) != EXPECTED_OPERATING_POINTS:
            raise ValueError("method must contain both operating points")
        return self


class ReportProvenance(BaseModel, frozen=True):
    model_config = ConfigDict(extra="allow")

    calibration_version: NonEmptyText
    dataset_hash: NonEmptyText


class EvaluationSummary(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2]
    counts: BenchmarkCounts
    methods: dict[str, MethodSummary]
    not_evaluated: list[NonEmptyText]
    provenance: ReportProvenance
    deployment_match: bool = False
    knowledge: KnowledgeEvaluationReport | None = None

    @model_validator(mode="after")
    def report_must_contain_all_methods(self) -> EvaluationSummary:
        if set(self.methods) != EXPECTED_METHODS:
            raise ValueError("report must contain exactly the three benchmark methods")
        if self.methods["entropy_cpd"].localization is None:
            raise ValueError("entropy_cpd must include localization metrics")
        if any(
            self.methods[method_id].localization is not None
            for method_id in ("global_nll", "window_nll")
        ):
            raise ValueError("NLL baselines must not claim CPD localization")
        return self


def _validate_safe_tree(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized_key = str(key).casefold()
            if normalized_key in FORBIDDEN_REPORT_FIELDS:
                raise UnsafeReportError(f"forbidden field in report: {normalized_key}")
            _validate_safe_tree(child)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _validate_safe_tree(child)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("report values must be finite")


class EvaluationReportService:
    def __init__(
        self,
        path: Path,
        *,
        knowledge_path: Path | None = None,
    ) -> None:
        self.path = path
        self.knowledge_path = knowledge_path

    def load(self, *, active_calibration_version: str | None) -> EvaluationSummary:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        _validate_safe_tree(raw)
        summary = EvaluationSummary.model_validate(raw)
        knowledge = None
        if self.knowledge_path is not None:
            knowledge_raw = json.loads(
                self.knowledge_path.read_text(encoding="ascii")
            )
            _validate_safe_tree(knowledge_raw)
            knowledge = KnowledgeEvaluationReport.model_validate(knowledge_raw)
            if (
                knowledge.hit_at_3 < 0.90
                or knowledge.citation_validity != 1.0
                or knowledge.decision_invariance != 1.0
            ):
                raise ValueError("knowledge evaluation acceptance gate failed")
        return summary.model_copy(
            update={
                "deployment_match": (
                    active_calibration_version is not None
                    and summary.provenance.calibration_version
                    == active_calibration_version
                ),
                "knowledge": knowledge,
            }
        )
