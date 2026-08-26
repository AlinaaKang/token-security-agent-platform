from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.evaluation.ablation import (
    SHA256_PATTERN,
    AblationMethod,
    AblationProfile,
    AgentAblationReport,
    EvaluationDomain,
    OperatingPoint,
    SourceCoverageStatus,
)


FORBIDDEN_KEYS = {
    "prompt",
    "suffix",
    "token_text",
    "raw_output",
    "guard_raw_output",
    "query_text",
}


class ArtifactValidationError(ValueError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceRevision(_StrictModel):
    source_id: str = Field(min_length=1)
    status: SourceCoverageStatus
    url: str | None = None
    revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    license_spdx: str | None = None
    attribution: str | None = None
    file_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    reason: str | None = None

    @field_validator("source_id")
    @classmethod
    def _normalize_source_id(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("source_id must not be blank")
        return normalized

    @model_validator(mode="after")
    def _validate_status_fields(self) -> "SourceRevision":
        if self.status is SourceCoverageStatus.VERIFIED:
            if not all(
                (
                    self.url,
                    self.revision,
                    self.license_spdx,
                    self.attribution,
                    self.file_sha256,
                )
            ):
                raise ValueError(
                    "verified sources require URL, revision, license, attribution, and file hash"
                )
            parsed = urlparse(self.url or "")
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError("verified source URL must use HTTPS")
            if self.reason is not None:
                raise ValueError("verified sources cannot have an unavailable reason")
        else:
            if self.reason is None or not self.reason.strip():
                raise ValueError("unverified sources require a reason")
            if self.file_sha256 is not None:
                raise ValueError("unverified sources cannot claim a verified file hash")
        return self


class AblationSplitManifest(_StrictModel):
    split: Literal["calibration", "dev", "test"]
    sample_ids: tuple[str, ...] = Field(min_length=1)
    group_ids: tuple[str, ...] = Field(min_length=1)
    domain_counts: dict[EvaluationDomain, int]
    family_counts: dict[str, int]

    @model_validator(mode="after")
    def _validate_counts_and_ids(self) -> "AblationSplitManifest":
        if len(set(self.sample_ids)) != len(self.sample_ids):
            raise ValueError("split sample IDs must be unique")
        if len(set(self.group_ids)) != len(self.group_ids):
            raise ValueError("split group IDs must be unique")
        if any(not item.strip() for item in (*self.sample_ids, *self.group_ids)):
            raise ValueError("split identifiers must not be blank")
        if any(count < 0 for count in self.domain_counts.values()):
            raise ValueError("domain counts must be non-negative")
        if sum(self.domain_counts.values()) != len(self.sample_ids):
            raise ValueError("domain counts must equal sample ID count")
        if any(not family.strip() or count <= 0 for family, count in self.family_counts.items()):
            raise ValueError("family counts require non-blank names and positive counts")
        optimized_count = self.domain_counts.get(EvaluationDomain.OPTIMIZED_SUFFIX, 0)
        if sum(self.family_counts.values()) > optimized_count:
            raise ValueError("family counts cannot exceed optimized suffix count")
        return self


class AblationBenchmarkManifest(_StrictModel):
    schema_version: Literal[1] = 1
    benchmark_version: str = Field(min_length=1)
    dataset_hash: str = Field(pattern=SHA256_PATTERN)
    split_seed: str = Field(min_length=1)
    sources: tuple[SourceRevision, ...] = Field(min_length=1)
    splits: tuple[AblationSplitManifest, ...] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def _validate_isolation(self) -> "AblationBenchmarkManifest":
        source_ids = [source.source_id for source in self.sources]
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("source IDs must be unique")
        split_names = [split.split for split in self.splits]
        if set(split_names) != {"calibration", "dev", "test"} or len(set(split_names)) != 3:
            raise ValueError("manifest requires calibration, dev, and test exactly once")

        seen_samples: set[str] = set()
        seen_groups: set[str] = set()
        for split in self.splits:
            sample_overlap = seen_samples.intersection(split.sample_ids)
            if sample_overlap:
                raise ValueError("sample IDs overlap across splits")
            group_overlap = seen_groups.intersection(split.group_ids)
            if group_overlap:
                raise ValueError("group IDs overlap across splits")
            seen_samples.update(split.sample_ids)
            seen_groups.update(split.group_ids)
        return self

    @property
    def source_coverage(self) -> dict[str, SourceCoverageStatus]:
        return {
            source.source_id: source.status
            for source in sorted(self.sources, key=lambda item: item.source_id)
        }

    def split(self, name: Literal["calibration", "dev", "test"]) -> AblationSplitManifest:
        return next(item for item in self.splits if item.split == name)


class AblationProfileBundle(_StrictModel):
    schema_version: Literal[1] = 1
    benchmark_version: str = Field(min_length=1)
    dataset_hash: str = Field(pattern=SHA256_PATTERN)
    profiles: tuple[AblationProfile, ...]

    @model_validator(mode="after")
    def _validate_profile_matrix(self) -> "AblationProfileBundle":
        expected = {
            (method, operating_point)
            for method in AblationMethod
            for operating_point in OperatingPoint
        }
        actual = {(profile.method, profile.operating_point) for profile in self.profiles}
        if len(self.profiles) != len(actual) or actual != expected:
            raise ValueError("profiles must contain each method/operating point exactly once")
        if any(profile.dataset_hash != self.dataset_hash for profile in self.profiles):
            raise ValueError("profile dataset hash mismatch within bundle")
        return self


def _scan_forbidden_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().casefold()
            if normalized in FORBIDDEN_KEYS:
                raise ArtifactValidationError(f"artifact contains forbidden key: {normalized}")
            _scan_forbidden_keys(nested)
    elif isinstance(value, list):
        for item in value:
            _scan_forbidden_keys(item)


def _load_json(path: Path) -> Any:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError("unable to read ablation artifact") from exc
    _scan_forbidden_keys(payload)
    return payload


def load_ablation_manifest(path: Path) -> AblationBenchmarkManifest:
    try:
        return AblationBenchmarkManifest.model_validate(_load_json(path))
    except ValidationError as exc:
        raise ArtifactValidationError(str(exc)) from exc


def load_ablation_profiles(
    path: Path, *, expected_dataset_hash: str
) -> tuple[AblationProfile, ...]:
    try:
        bundle = AblationProfileBundle.model_validate(_load_json(path))
    except ValidationError as exc:
        raise ArtifactValidationError(str(exc)) from exc
    if bundle.dataset_hash != expected_dataset_hash:
        raise ArtifactValidationError("profile dataset hash mismatch")
    return bundle.profiles


def load_ablation_report(
    path: Path,
    *,
    expected_benchmark_version: str,
    expected_dataset_hash: str,
) -> AgentAblationReport:
    try:
        report = AgentAblationReport.model_validate(_load_json(path))
    except ValidationError as exc:
        raise ArtifactValidationError(str(exc)) from exc
    if report.benchmark_version != expected_benchmark_version:
        raise ArtifactValidationError("ablation report benchmark version mismatch")
    if report.dataset_hash != expected_dataset_hash:
        raise ArtifactValidationError("ablation report dataset hash mismatch")
    return report


def write_ascii_json(path: Path, payload: BaseModel) -> None:
    serialized = (
        json.dumps(
            payload.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")

    if path.exists():
        existing = _load_json(path)
        new_identity = payload.model_dump(mode="json")
        for key in ("benchmark_version", "dataset_hash"):
            if existing.get(key) != new_identity.get(key):
                raise ArtifactValidationError(
                    "refusing to overwrite artifact with a different identity"
                )

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(serialized)
    temporary.replace(path)
