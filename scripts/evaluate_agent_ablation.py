from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.evaluation.ablation import AgentAblationReport, evaluate_ablation
from app.evaluation.ablation_io import (
    load_ablation_manifest,
    load_ablation_profiles,
    write_ascii_json,
)
from scripts.select_ablation_profiles import load_observations


class _FailureRow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_id: str = Field(min_length=1)
    error_type: str = Field(min_length=1)

    @field_validator("sample_id")
    @classmethod
    def _strip_sample_id(cls, value: str) -> str:
        return value.strip()

    @field_validator("error_type")
    @classmethod
    def _normalize_error(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if not normalized.replace("_", "").isalnum():
            raise ValueError("error_type must be a normalized identifier")
        return normalized


def _load_failures(path: Path) -> tuple[_FailureRow, ...]:
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
        if not isinstance(payload, list):
            raise ValueError
        rows = tuple(_FailureRow.model_validate(item) for item in payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise ValueError("protected failure summary is invalid") from None
    if len({row.sample_id for row in rows}) != len(rows):
        raise ValueError("protected failure sample IDs must be unique")
    return rows


def evaluate_test(
    *,
    manifest_path: Path,
    profiles_path: Path,
    observations_path: Path,
    errors_path: Path,
    output_path: Path,
) -> AgentAblationReport:
    manifest = load_ablation_manifest(manifest_path)
    profiles = load_ablation_profiles(
        profiles_path, expected_dataset_hash=manifest.dataset_hash
    )
    observations = load_observations(observations_path)
    failures = _load_failures(errors_path)
    expected = set(manifest.split("test").sample_ids)
    observation_ids = {row.sample_id for row in observations}
    failure_ids = {row.sample_id for row in failures}
    if observation_ids.intersection(failure_ids):
        raise ValueError("test observation and failure IDs must be disjoint")
    if observation_ids.union(failure_ids) != expected:
        raise ValueError("test observation IDs and failures must match the frozen manifest")
    if any(row.split != "test" for row in observations):
        raise ValueError("test evaluation accepts test observations only")

    failure_counts = Counter(row.error_type for row in failures)
    report = evaluate_ablation(
        observations,
        profiles,
        benchmark_version=manifest.benchmark_version,
        dataset_hash=manifest.dataset_hash,
        source_coverage=manifest.source_coverage,
        requested_count=len(expected),
        failure_counts=dict(sorted(failure_counts.items())),
    )
    write_ascii_json(output_path, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate frozen agent ablation profiles on test observations"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--observations-jsonl", type=Path, required=True)
    parser.add_argument("--errors", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = evaluate_test(
        manifest_path=args.manifest,
        profiles_path=args.profiles,
        observations_path=args.observations_jsonl,
        errors_path=args.errors,
        output_path=args.output,
    )
    print(
        "agent ablation completed "
        f"requested={report.requested_count} completed={report.completed_count} "
        f"failed={report.failed_count}"
    )


if __name__ == "__main__":
    main()
