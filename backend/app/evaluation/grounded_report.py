from __future__ import annotations

import hashlib
import math
import platform
import statistics
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.agent.fusion import FusionReason
from app.knowledge.models import (
    KnowledgeSnapshot,
    NormalizedSecurityFacts,
    ReportStatus,
)
from app.knowledge.query import RetrievalMetadata, SafeQueryBuilder
from app.knowledge.reporting import (
    QwenGroundedReportGenerator,
    ReportFailureCode,
)
from app.knowledge.retriever import LocalKnowledgeRetriever
from app.schemas import Decision
from app.semantic.models import SemanticCategory, SemanticSeverity


ExperimentPhase = Literal["development", "test"]
SelectionRule = Literal[
    "p95_budget_generated_rate_citation_latency_size"
]
SELECTION_RULE: SelectionRule = (
    "p95_budget_generated_rate_citation_latency_size"
)
FAILURE_CODES: tuple[ReportFailureCode, ...] = (
    "runtime_timeout",
    "runtime_error",
    "invalid_report_json",
    "invalid_report_schema",
    "invalid_report_citation",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReportExperimentConfig(_StrictModel):
    max_new_tokens: Literal[64, 96, 128]
    timeout_seconds: Literal[3.0, 5.0, 6.0]


CANDIDATE_REPORT_CONFIGS: tuple[ReportExperimentConfig, ...] = tuple(
    ReportExperimentConfig(max_new_tokens=tokens, timeout_seconds=timeout)
    for tokens in (64, 96, 128)
    for timeout in (3.0, 5.0, 6.0)
)


class SelectedReportConfig(_StrictModel):
    schema_version: Literal[1] = 1
    snapshot_version: str = Field(min_length=1)
    max_new_tokens: Literal[64, 96, 128]
    timeout_seconds: Literal[3.0, 5.0, 6.0]
    selection_rule: SelectionRule = SELECTION_RULE

    @property
    def experiment_config(self) -> ReportExperimentConfig:
        return ReportExperimentConfig(
            max_new_tokens=self.max_new_tokens,
            timeout_seconds=self.timeout_seconds,
        )


def load_selected_report_config(path: Path) -> SelectedReportConfig:
    if not path.is_file():
        raise FileNotFoundError(f"selected report config does not exist: {path}")
    return SelectedReportConfig.model_validate_json(path.read_text(encoding="utf-8"))


class ReportEvaluationSample(_StrictModel):
    sample_id: str = Field(min_length=1, exclude=True, repr=False)
    family: str = Field(min_length=1)
    prompt: str = Field(min_length=1, exclude=True, repr=False)
    suffix_char_start: int = Field(ge=1, exclude=True, repr=False)
    decision: Decision = Field(default=Decision.BLOCK, exclude=True)

    @field_validator("family")
    @classmethod
    def normalize_family(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("report sample family must not be blank")
        return normalized

    @model_validator(mode="after")
    def suffix_start_must_be_inside_prompt(self) -> "ReportEvaluationSample":
        if self.suffix_char_start >= len(self.prompt):
            raise ValueError("report sample suffix start must be inside prompt")
        return self


class ReportExperimentMetrics(_StrictModel):
    total_count: int = Field(gt=0)
    generated_count: int = Field(ge=0)
    fallback_count: int = Field(ge=0)
    generated_rate: float = Field(ge=0, le=1, allow_inf_nan=False)
    citation_validity: float = Field(ge=0, le=1, allow_inf_nan=False)
    action_invariance: float = Field(ge=0, le=1, allow_inf_nan=False)
    latency_p50_ms: float = Field(ge=0, allow_inf_nan=False)
    latency_p95_ms: float = Field(ge=0, allow_inf_nan=False)
    failure_counts: dict[ReportFailureCode, int]
    family_counts: dict[str, int]

    @model_validator(mode="after")
    def validate_aggregate_integrity(self) -> "ReportExperimentMetrics":
        if self.generated_count + self.fallback_count != self.total_count:
            raise ValueError("generated plus fallback must equal total")
        if self.generated_rate != self.generated_count / self.total_count:
            raise ValueError("generated rate must match aggregate counts")
        if set(self.failure_counts) != set(FAILURE_CODES):
            raise ValueError("failure counts must contain every fixed failure code")
        if any(count < 0 for count in self.failure_counts.values()):
            raise ValueError("failure counts must not be negative")
        if sum(self.failure_counts.values()) != self.fallback_count:
            raise ValueError("failure counts must sum to fallback count")
        if not self.family_counts or any(
            not family.strip() or count <= 0
            for family, count in self.family_counts.items()
        ):
            raise ValueError("family counts must be positive")
        if sum(self.family_counts.values()) != self.total_count:
            raise ValueError("family counts must sum to total")
        return self


class ReportConfigResult(_StrictModel):
    config: ReportExperimentConfig
    metrics: ReportExperimentMetrics


class ReportTargetStatus(_StrictModel):
    generated_rate: bool
    citation_validity: bool
    action_invariance: bool
    latency_p95_ms: bool


class ReportExperimentReport(_StrictModel):
    schema_version: Literal[1] = 1
    phase: ExperimentPhase
    snapshot_version: str = Field(min_length=1)
    snapshot_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    model_version: str = Field(min_length=1)
    selection_rule: SelectionRule = SELECTION_RULE
    candidate_results: tuple[ReportConfigResult, ...] = Field(min_length=1)
    selected_config: ReportExperimentConfig
    metrics: ReportExperimentMetrics
    target_status: ReportTargetStatus
    runtime_versions: dict[str, str]

    @model_validator(mode="after")
    def selected_metrics_must_be_a_candidate(self) -> "ReportExperimentReport":
        matches = [
            result
            for result in self.candidate_results
            if result.config == self.selected_config
        ]
        if len(matches) != 1 or matches[0].metrics != self.metrics:
            raise ValueError("selected metrics must match exactly one candidate")
        expected_count = 9 if self.phase == "development" else 1
        if len(self.candidate_results) != expected_count:
            raise ValueError(
                f"{self.phase} report requires {expected_count} candidate results"
            )
        return self


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        raise ValueError("latency values must not be empty")
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return float(ordered[index])


def _facts(sample: ReportEvaluationSample) -> NormalizedSecurityFacts:
    return NormalizedSecurityFacts(
        semantic_severity=SemanticSeverity.UNSAFE,
        semantic_categories=(SemanticCategory.JAILBREAK,),
        detector_status="token_anomaly_candidate",
        anomaly_char_start=sample.suffix_char_start,
        fusion_reason=FusionReason.CPD_CANDIDATE,
        decision=sample.decision.value,
        mode="analysis",
        attack_family=sample.family,
    )


def evaluate_report_config(
    samples: Sequence[ReportEvaluationSample],
    *,
    snapshot: KnowledgeSnapshot,
    runtime: object,
    config: ReportExperimentConfig,
    clock: Callable[[], float] = time.perf_counter,
) -> ReportConfigResult:
    rows = tuple(samples)
    if not rows:
        raise ValueError("report evaluation samples must not be empty")
    identifiers = [row.sample_id for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("report evaluation sample IDs must be unique")

    retriever = LocalKnowledgeRetriever(snapshot)
    query_builder = SafeQueryBuilder()
    generator = QwenGroundedReportGenerator(
        runtime,
        max_new_tokens=config.max_new_tokens,
        max_time_seconds=config.timeout_seconds,
    )
    generated_count = 0
    valid_citations = 0
    citation_count = 0
    invariant_count = 0
    failure_counts: Counter[str] = Counter({code: 0 for code in FAILURE_CODES})
    family_counts: Counter[str] = Counter()
    latencies: list[float] = []

    for sample in rows:
        facts = _facts(sample)
        metadata = RetrievalMetadata(
            semantic_severity=facts.semantic_severity,
            semantic_categories=facts.semantic_categories,
            detector_status=facts.detector_status,
            fusion_reason=facts.fusion_reason,
            decision=sample.decision,
            mode="analysis",
            attack_family=sample.family,
        )
        query = query_builder.build(
            sample.prompt,
            char_onset=sample.suffix_char_start,
            metadata=metadata,
        )
        evidence = retriever.search(query, top_k=3)
        if not evidence:
            raise RuntimeError("report evaluation retrieval returned no evidence")

        decision_before = facts.decision
        started = clock()
        generation = generator.generate(facts, evidence)
        latencies.append((clock() - started) * 1000)
        decision_after = facts.decision
        invariant_count += decision_before == decision_after
        family_counts[sample.family] += 1

        allowed_ids = {item.knowledge_id for item in evidence}
        citations = generation.report.evidence_ids
        citation_count += len(citations)
        valid_citations += sum(item in allowed_ids for item in citations)
        if generation.status is ReportStatus.GENERATED:
            generated_count += 1
        else:
            if generation.failure_code not in FAILURE_CODES:
                raise RuntimeError("report fallback returned an unknown failure code")
            failure_counts[generation.failure_code] += 1

    total_count = len(rows)
    metrics = ReportExperimentMetrics(
        total_count=total_count,
        generated_count=generated_count,
        fallback_count=total_count - generated_count,
        generated_rate=generated_count / total_count,
        citation_validity=(
            valid_citations / citation_count if citation_count else 1.0
        ),
        action_invariance=invariant_count / total_count,
        latency_p50_ms=_percentile(latencies, 0.50),
        latency_p95_ms=_percentile(latencies, 0.95),
        failure_counts={
            code: int(failure_counts[code]) for code in FAILURE_CODES
        },
        family_counts=dict(sorted(family_counts.items())),
    )
    return ReportConfigResult(config=config, metrics=metrics)


def select_report_config(
    results: Sequence[ReportConfigResult],
) -> ReportExperimentConfig:
    candidates = tuple(results)
    if not candidates:
        raise ValueError("report config selection requires candidate results")
    if len({result.config for result in candidates}) != len(candidates):
        raise ValueError("report config selection contains duplicate candidates")

    def rank(result: ReportConfigResult) -> tuple[bool, float, float, float, int, float]:
        metrics = result.metrics
        return (
            metrics.latency_p95_ms <= 5000.0,
            metrics.generated_rate,
            metrics.citation_validity,
            -metrics.latency_p95_ms,
            -result.config.max_new_tokens,
            -result.config.timeout_seconds,
        )

    return max(candidates, key=rank).config


def build_experiment_report(
    *,
    phase: ExperimentPhase,
    snapshot: KnowledgeSnapshot,
    model_version: str,
    candidate_results: Sequence[ReportConfigResult],
    selected_config: ReportExperimentConfig,
) -> ReportExperimentReport:
    results = tuple(candidate_results)
    selected = next(
        (result for result in results if result.config == selected_config),
        None,
    )
    if selected is None:
        raise ValueError("selected config is absent from candidate results")
    metrics = selected.metrics
    return ReportExperimentReport(
        phase=phase,
        snapshot_version=snapshot.manifest.snapshot_version,
        snapshot_hash=snapshot.manifest.cards_sha256,
        model_version=model_version,
        candidate_results=results,
        selected_config=selected_config,
        metrics=metrics,
        target_status=ReportTargetStatus(
            generated_rate=metrics.generated_rate >= 0.90,
            citation_validity=metrics.citation_validity == 1.0,
            action_invariance=metrics.action_invariance == 1.0,
            latency_p95_ms=metrics.latency_p95_ms <= 5000.0,
        ),
        runtime_versions={"python": platform.python_version()},
    )


def assert_disjoint_sample_ids(
    development_ids: Iterable[str], test_ids: Iterable[str]
) -> None:
    def digest(value: str) -> bytes:
        return hashlib.sha256(("advanced-v2:" + value).encode("utf-8")).digest()

    development_hashes = {digest(value) for value in development_ids}
    test_hashes = {digest(value) for value in test_ids}
    if development_hashes.intersection(test_hashes):
        raise ValueError("development and frozen test sample overlap")
