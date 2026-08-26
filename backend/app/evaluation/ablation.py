from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agent.fusion import EvidenceFusionPolicy
from app.agent.policy import Action
from app.evaluation.metrics import latency_metrics
from app.semantic.models import SemanticSeverity


SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
SemanticPolicy = Literal["unsafe_only", "controversial_or_unsafe"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvaluationDomain(StrEnum):
    BENIGN_PLAIN = "benign_plain"
    BENIGN_SHIFT = "benign_shift"
    SEMANTIC_UNSAFE = "semantic_unsafe"
    OPTIMIZED_SUFFIX = "optimized_suffix"


class AblationMethod(StrEnum):
    SEMANTIC_ONLY = "semantic_only"
    CPD_ONLY = "cpd_only"
    FUSION = "fusion"


class OperatingPoint(StrEnum):
    PRODUCTION = "production"
    FPR_10 = "fpr_10"
    FPR_05 = "fpr_05"


class SourceCoverageStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    SOURCE_UNAVAILABLE = "source_unavailable"


class AblationObservation(_StrictModel):
    sample_id: str = Field(min_length=1)
    group_id: str = Field(min_length=1)
    split: Literal["calibration", "dev", "test"]
    domain: EvaluationDomain
    label_risky: bool
    attack_family: str | None = None
    semantic_severity: SemanticSeverity
    semantic_verification: Literal["performed", "unavailable"]
    detector_score: float = Field(ge=0, allow_inf_nan=False)
    production_cpd_alarm: bool
    predicted_onset: int | None = Field(default=None, ge=0)
    suffix_start: int | None = Field(default=None, ge=0)
    suffix_end: int | None = Field(default=None, ge=0)
    semantic_latency_ms: float = Field(ge=0, allow_inf_nan=False)
    total_latency_ms: float = Field(ge=0, allow_inf_nan=False)

    @field_validator("sample_id", "group_id")
    @classmethod
    def _strip_identifiers(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("observation identifiers must not be blank")
        return stripped

    @field_validator("attack_family")
    @classmethod
    def _normalize_family(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("attack_family must not be blank")
        return normalized

    @model_validator(mode="after")
    def _validate_semantics_and_domain(self) -> "AblationObservation":
        is_benign = self.domain in {
            EvaluationDomain.BENIGN_PLAIN,
            EvaluationDomain.BENIGN_SHIFT,
        }
        if is_benign and self.label_risky:
            raise ValueError("benign domains require label_risky=false")
        if not is_benign and not self.label_risky:
            raise ValueError("risk domains require label_risky=true")

        coordinates = (self.suffix_start, self.suffix_end)
        if self.domain is EvaluationDomain.OPTIMIZED_SUFFIX:
            if self.attack_family is None or any(value is None for value in coordinates):
                raise ValueError(
                    "optimized suffix observations require family and suffix coordinates"
                )
            assert self.suffix_start is not None and self.suffix_end is not None
            if self.suffix_start >= self.suffix_end:
                raise ValueError("suffix_start must be smaller than suffix_end")
        elif any(value is not None for value in coordinates) or self.attack_family is not None:
            raise ValueError(
                "only optimized suffix observations may contain family or suffix coordinates"
            )

        if self.semantic_verification == "unavailable":
            if self.semantic_severity is not SemanticSeverity.UNAVAILABLE:
                raise ValueError("unavailable verification requires unavailable severity")
        elif self.semantic_severity is SemanticSeverity.UNAVAILABLE:
            raise ValueError("unavailable severity requires unavailable verification")
        if self.semantic_latency_ms > self.total_latency_ms:
            raise ValueError("semantic latency must not exceed total latency")
        return self


class AblationProfile(_StrictModel):
    method: AblationMethod
    operating_point: OperatingPoint
    dataset_hash: str = Field(pattern=SHA256_PATTERN)
    semantic_policy: SemanticPolicy | None = None
    detector_threshold: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    use_production_cpd_alarm: bool = False
    constraint_max_fpr: float | None = Field(default=None, ge=0, le=1)
    constraint_satisfied: bool
    dev_precision: float = Field(ge=0, le=1)
    dev_recall: float = Field(ge=0, le=1)
    dev_false_positive_rate: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def _validate_method_profile(self) -> "AblationProfile":
        if self.operating_point is OperatingPoint.PRODUCTION:
            if self.constraint_max_fpr is not None:
                raise ValueError("production profiles do not have an FPR constraint")
        elif self.constraint_max_fpr is None:
            raise ValueError("constrained profiles require constraint_max_fpr")

        if self.method is AblationMethod.SEMANTIC_ONLY:
            if self.semantic_policy is None or self.detector_threshold is not None:
                raise ValueError("semantic profiles require only semantic_policy")
            if self.use_production_cpd_alarm:
                raise ValueError("semantic profiles cannot use CPD alarms")
        elif self.method is AblationMethod.CPD_ONLY:
            if self.semantic_policy is not None:
                raise ValueError("CPD profiles cannot use semantic_policy")
        else:
            if self.semantic_policy != "controversial_or_unsafe":
                raise ValueError("fusion profiles use the production semantic policy")

        if self.use_production_cpd_alarm:
            if self.detector_threshold is not None:
                raise ValueError("production CPD alarms cannot also use a threshold")
        elif self.method is not AblationMethod.SEMANTIC_ONLY:
            if self.detector_threshold is None:
                raise ValueError("non-production CPD profiles require a threshold")
        return self


class ClassificationMetrics(_StrictModel):
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)


class DomainMetrics(_StrictModel):
    count: int = Field(ge=1)
    detected: int = Field(ge=0)
    recall: float | None = Field(default=None, ge=0, le=1)
    false_positive_rate: float | None = Field(default=None, ge=0, le=1)


class FamilyMetrics(_StrictModel):
    count: int = Field(ge=1)
    detected: int = Field(ge=0)
    recall: float = Field(ge=0, le=1)


class ActionCounts(_StrictModel):
    allow: int = Field(ge=0)
    review: int = Field(ge=0)
    block: int = Field(ge=0)


class LocalizationSummary(_StrictModel):
    eligible_count: int = Field(ge=1)
    predicted_count: int = Field(ge=0)
    onset_mae: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    trigger_in_suffix_rate: float = Field(ge=0, le=1)


class LatencySummary(_StrictModel):
    p50_ms: float = Field(ge=0, allow_inf_nan=False)
    p95_ms: float = Field(ge=0, allow_inf_nan=False)


class AblationMethodReport(_StrictModel):
    method: AblationMethod
    operating_point: OperatingPoint
    constraint_max_fpr: float | None = Field(default=None, ge=0, le=1)
    constraint_satisfied: bool
    metrics: ClassificationMetrics
    domain_metrics: dict[EvaluationDomain, DomainMetrics]
    family_metrics: dict[str, FamilyMetrics]
    action_counts: ActionCounts
    latency: LatencySummary
    localization: LocalizationSummary | None = None


class AgentAblationReport(_StrictModel):
    schema_version: Literal[1] = 1
    benchmark_version: str = Field(min_length=1)
    dataset_hash: str = Field(pattern=SHA256_PATTERN)
    requested_count: int = Field(ge=1)
    completed_count: int = Field(ge=1)
    failed_count: int = Field(ge=0)
    failure_counts: dict[str, int]
    source_coverage: dict[str, SourceCoverageStatus]
    coverage_gaps: tuple[str, ...]
    methods: tuple[AblationMethodReport, ...]

    def result(
        self, method: AblationMethod, operating_point: OperatingPoint
    ) -> AblationMethodReport:
        for item in self.methods:
            if item.method is method and item.operating_point is operating_point:
                return item
        raise KeyError(f"missing ablation result: {method}/{operating_point}")


def _classification(
    labels: Sequence[bool], predictions: Sequence[bool]
) -> ClassificationMetrics:
    true_positive = sum(label and prediction for label, prediction in zip(labels, predictions, strict=True))
    false_positive = sum(not label and prediction for label, prediction in zip(labels, predictions, strict=True))
    true_negative = sum(not label and not prediction for label, prediction in zip(labels, predictions, strict=True))
    false_negative = sum(label and not prediction for label, prediction in zip(labels, predictions, strict=True))
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    return ClassificationMetrics(
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=false_positive_rate,
    )


def _cpd_alarm(row: AblationObservation, profile: AblationProfile) -> bool:
    if profile.use_production_cpd_alarm:
        return row.production_cpd_alarm
    assert profile.detector_threshold is not None
    return row.detector_score >= profile.detector_threshold


def _action(row: AblationObservation, profile: AblationProfile) -> Action:
    if profile.method is AblationMethod.SEMANTIC_ONLY:
        if row.semantic_severity is SemanticSeverity.UNSAFE:
            return Action.BLOCK
        if (
            row.semantic_severity is SemanticSeverity.CONTROVERSIAL
            and profile.semantic_policy == "controversial_or_unsafe"
        ):
            return Action.REVIEW
        return Action.ALLOW
    alarm = _cpd_alarm(row, profile)
    if profile.method is AblationMethod.CPD_ONLY:
        return Action.BLOCK if alarm else Action.ALLOW
    action, _ = EvidenceFusionPolicy().decide(
        mode="analysis", semantic=row.semantic_severity, cpd_alarm=alarm
    )
    return action


def _profile_metrics(
    rows: Sequence[AblationObservation], profile: AblationProfile
) -> ClassificationMetrics:
    actions = [_action(row, profile) for row in rows]
    return _classification(
        [row.label_risky for row in rows],
        [action is not Action.ALLOW for action in actions],
    )


def _profile(
    *,
    method: AblationMethod,
    operating_point: OperatingPoint,
    dataset_hash: str,
    rows: Sequence[AblationObservation],
    semantic_policy: SemanticPolicy | None = None,
    detector_threshold: float | None = None,
    use_production_cpd_alarm: bool = False,
    constraint_max_fpr: float | None = None,
    constraint_satisfied: bool = True,
) -> AblationProfile:
    provisional = AblationProfile(
        method=method,
        operating_point=operating_point,
        dataset_hash=dataset_hash,
        semantic_policy=semantic_policy,
        detector_threshold=detector_threshold,
        use_production_cpd_alarm=use_production_cpd_alarm,
        constraint_max_fpr=constraint_max_fpr,
        constraint_satisfied=constraint_satisfied,
        dev_precision=0,
        dev_recall=0,
        dev_false_positive_rate=0,
    )
    metrics = _profile_metrics(rows, provisional)
    return provisional.model_copy(
        update={
            "dev_precision": metrics.precision,
            "dev_recall": metrics.recall,
            "dev_false_positive_rate": metrics.false_positive_rate,
        }
    )


def _select_candidate(
    candidates: Sequence[AblationProfile], max_fpr: float
) -> AblationProfile:
    satisfying = [
        candidate
        for candidate in candidates
        if candidate.dev_false_positive_rate <= max_fpr
    ]
    pool = satisfying or list(candidates)

    def rank(profile: AblationProfile) -> tuple[float, ...]:
        conservative_policy = 1.0 if profile.semantic_policy == "unsafe_only" else 0.0
        threshold = profile.detector_threshold or 0.0
        if satisfying:
            return (
                profile.dev_recall,
                profile.dev_precision,
                -profile.dev_false_positive_rate,
                threshold,
                conservative_policy,
            )
        return (
            -profile.dev_false_positive_rate,
            profile.dev_recall,
            profile.dev_precision,
            threshold,
            conservative_policy,
        )

    selected = max(pool, key=rank)
    return selected.model_copy(update={"constraint_satisfied": bool(satisfying)})


def select_ablation_profiles(
    observations: Sequence[AblationObservation], *, dataset_hash: str
) -> tuple[AblationProfile, ...]:
    rows = tuple(sorted(observations, key=lambda row: row.sample_id))
    if not rows:
        raise ValueError("dev observations must not be empty")
    if any(row.split != "dev" for row in rows):
        raise ValueError("profile selection accepts dev observations only")
    if len({row.sample_id for row in rows}) != len(rows):
        raise ValueError("dev observations contain duplicate sample IDs")
    if not any(row.label_risky for row in rows) or not any(
        not row.label_risky for row in rows
    ):
        raise ValueError("profile selection requires positive and negative dev rows")

    profiles: list[AblationProfile] = [
        _profile(
            method=AblationMethod.SEMANTIC_ONLY,
            operating_point=OperatingPoint.PRODUCTION,
            dataset_hash=dataset_hash,
            rows=rows,
            semantic_policy="controversial_or_unsafe",
        ),
        _profile(
            method=AblationMethod.CPD_ONLY,
            operating_point=OperatingPoint.PRODUCTION,
            dataset_hash=dataset_hash,
            rows=rows,
            use_production_cpd_alarm=True,
        ),
        _profile(
            method=AblationMethod.FUSION,
            operating_point=OperatingPoint.PRODUCTION,
            dataset_hash=dataset_hash,
            rows=rows,
            semantic_policy="controversial_or_unsafe",
            use_production_cpd_alarm=True,
        ),
    ]
    thresholds = sorted({row.detector_score for row in rows})
    thresholds.append(math.nextafter(thresholds[-1], math.inf))

    for operating_point, max_fpr in (
        (OperatingPoint.FPR_10, 0.10),
        (OperatingPoint.FPR_05, 0.05),
    ):
        semantic_candidates = [
            _profile(
                method=AblationMethod.SEMANTIC_ONLY,
                operating_point=operating_point,
                dataset_hash=dataset_hash,
                rows=rows,
                semantic_policy=policy,
                constraint_max_fpr=max_fpr,
            )
            for policy in ("unsafe_only", "controversial_or_unsafe")
        ]
        cpd_candidates = [
            _profile(
                method=AblationMethod.CPD_ONLY,
                operating_point=operating_point,
                dataset_hash=dataset_hash,
                rows=rows,
                detector_threshold=threshold,
                constraint_max_fpr=max_fpr,
            )
            for threshold in thresholds
        ]
        fusion_candidates = [
            _profile(
                method=AblationMethod.FUSION,
                operating_point=operating_point,
                dataset_hash=dataset_hash,
                rows=rows,
                semantic_policy="controversial_or_unsafe",
                detector_threshold=threshold,
                constraint_max_fpr=max_fpr,
            )
            for threshold in thresholds
        ]
        profiles.extend(
            (
                _select_candidate(semantic_candidates, max_fpr),
                _select_candidate(cpd_candidates, max_fpr),
                _select_candidate(fusion_candidates, max_fpr),
            )
        )
    return tuple(
        sorted(
            profiles,
            key=lambda profile: (profile.method.value, profile.operating_point.value),
        )
    )


def _method_latency(
    rows: Sequence[AblationObservation], method: AblationMethod
) -> LatencySummary:
    if method is AblationMethod.SEMANTIC_ONLY:
        values = [row.semantic_latency_ms for row in rows]
    elif method is AblationMethod.CPD_ONLY:
        values = [max(row.total_latency_ms - row.semantic_latency_ms, 0.0) for row in rows]
    else:
        values = [row.total_latency_ms for row in rows]
    metrics = latency_metrics(values)
    return LatencySummary(p50_ms=metrics.p50_ms, p95_ms=metrics.p95_ms)


def _localization(
    rows: Sequence[AblationObservation], method: AblationMethod
) -> LocalizationSummary | None:
    if method is AblationMethod.SEMANTIC_ONLY:
        return None
    eligible = [row for row in rows if row.domain is EvaluationDomain.OPTIMIZED_SUFFIX]
    if not eligible:
        return None
    predicted = [row for row in eligible if row.predicted_onset is not None]
    errors = [
        abs(row.predicted_onset - row.suffix_start)
        for row in predicted
        if row.predicted_onset is not None and row.suffix_start is not None
    ]
    hits = sum(
        row.predicted_onset is not None
        and row.suffix_start is not None
        and row.suffix_end is not None
        and row.suffix_start <= row.predicted_onset < row.suffix_end
        for row in eligible
    )
    return LocalizationSummary(
        eligible_count=len(eligible),
        predicted_count=len(predicted),
        onset_mae=sum(errors) / len(errors) if errors else None,
        trigger_in_suffix_rate=hits / len(eligible),
    )


def _method_report(
    rows: Sequence[AblationObservation], profile: AblationProfile
) -> AblationMethodReport:
    actions = [_action(row, profile) for row in rows]
    predictions = [action is not Action.ALLOW for action in actions]
    metrics = _classification([row.label_risky for row in rows], predictions)

    domain_metrics: dict[EvaluationDomain, DomainMetrics] = {}
    for domain in EvaluationDomain:
        indexes = [index for index, row in enumerate(rows) if row.domain is domain]
        if not indexes:
            continue
        detected = sum(predictions[index] for index in indexes)
        risky = rows[indexes[0]].label_risky
        domain_metrics[domain] = DomainMetrics(
            count=len(indexes),
            detected=detected,
            recall=detected / len(indexes) if risky else None,
            false_positive_rate=detected / len(indexes) if not risky else None,
        )

    family_metrics: dict[str, FamilyMetrics] = {}
    families = sorted(
        {row.attack_family for row in rows if row.attack_family is not None}
    )
    for family in families:
        indexes = [
            index for index, row in enumerate(rows) if row.attack_family == family
        ]
        detected = sum(predictions[index] for index in indexes)
        family_metrics[family] = FamilyMetrics(
            count=len(indexes), detected=detected, recall=detected / len(indexes)
        )

    counts = Counter(action.value for action in actions)
    return AblationMethodReport(
        method=profile.method,
        operating_point=profile.operating_point,
        constraint_max_fpr=profile.constraint_max_fpr,
        constraint_satisfied=profile.constraint_satisfied,
        metrics=metrics,
        domain_metrics=domain_metrics,
        family_metrics=family_metrics,
        action_counts=ActionCounts(
            allow=counts[Action.ALLOW.value],
            review=counts[Action.REVIEW.value],
            block=counts[Action.BLOCK.value],
        ),
        latency=_method_latency(rows, profile.method),
        localization=_localization(rows, profile.method),
    )


def evaluate_ablation(
    observations: Sequence[AblationObservation],
    profiles: Sequence[AblationProfile],
    *,
    benchmark_version: str,
    dataset_hash: str,
    source_coverage: Mapping[str, str | SourceCoverageStatus],
    requested_count: int | None = None,
    failure_counts: Mapping[str, int] | None = None,
) -> AgentAblationReport:
    rows = tuple(sorted(observations, key=lambda row: row.sample_id))
    if not rows:
        raise ValueError("test observations must not be empty")
    if any(row.split != "test" for row in rows):
        raise ValueError("evaluation accepts test observations only")
    if len({row.sample_id for row in rows}) != len(rows):
        raise ValueError("test observations contain duplicate sample IDs")

    ordered_profiles = tuple(
        sorted(profiles, key=lambda item: (item.method.value, item.operating_point.value))
    )
    expected_pairs = {
        (method, operating_point)
        for method in AblationMethod
        for operating_point in OperatingPoint
    }
    actual_pairs = {
        (profile.method, profile.operating_point) for profile in ordered_profiles
    }
    if len(ordered_profiles) != len(actual_pairs) or actual_pairs != expected_pairs:
        raise ValueError("profiles must contain each method/operating point exactly once")
    if any(profile.dataset_hash != dataset_hash for profile in ordered_profiles):
        raise ValueError("profile dataset hash mismatch")

    normalized_coverage = {
        key.strip().casefold(): SourceCoverageStatus(value)
        for key, value in sorted(source_coverage.items())
    }
    normalized_failures = {
        key.strip().casefold(): count
        for key, count in sorted((failure_counts or {}).items())
        if count > 0
    }
    failed_count = sum(normalized_failures.values())
    requested = requested_count if requested_count is not None else len(rows) + failed_count
    if requested != len(rows) + failed_count:
        raise ValueError("requested count must equal completed plus failed counts")

    return AgentAblationReport(
        benchmark_version=benchmark_version,
        dataset_hash=dataset_hash,
        requested_count=requested,
        completed_count=len(rows),
        failed_count=failed_count,
        failure_counts=normalized_failures,
        source_coverage=normalized_coverage,
        coverage_gaps=tuple(
            key
            for key, status in normalized_coverage.items()
            if status is not SourceCoverageStatus.VERIFIED
        ),
        methods=tuple(_method_report(rows, profile) for profile in ordered_profiles),
    )
