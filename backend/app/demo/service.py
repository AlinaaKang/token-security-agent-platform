from __future__ import annotations

import csv
import hashlib
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.evaluation.normalize import (
    CPDonlineAdapter,
    CPDonlineGuardBypassAdapter,
    CPDonlineOptimizationAdapter,
    PromptRecord,
    RowAdapter,
)
from app.evaluation.split import split_by_group
from app.schemas import AnalysisRequest, AnalysisResult, NonEmptyText


class DemoSampleNotFound(LookupError):
    pass


class DemoSampleSummary(BaseModel, frozen=True):
    sample_id: NonEmptyText
    family: NonEmptyText
    split: Literal["test"] = "test"
    evaluated: bool = True


class DemoAnalysisResult(BaseModel, frozen=True):
    sample_id: NonEmptyText
    family: NonEmptyText
    split: Literal["test"] = "test"
    dataset_commit: NonEmptyText
    result: AnalysisResult


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _convert_unique(
    rows: Iterable[Mapping[str, Any]], adapter: RowAdapter
) -> list[PromptRecord]:
    records: dict[str, PromptRecord] = {}
    for row in rows:
        record = adapter.convert(row)
        existing = records.get(record.sample_id)
        if existing is None:
            records[record.sample_id] = record
        elif existing != record:
            raise ValueError("demo source contains conflicting sample IDs")
    return list(records.values())


class DemoSampleService:
    def __init__(self, *, records: list[PromptRecord], source_commit: str) -> None:
        if not source_commit.strip():
            raise ValueError("source_commit must not be blank")
        test_records = split_by_group(records, seed="competition-v1").test
        self._records = {
            record.sample_id: record
            for record in test_records
            if record.label_suffix_attack and record.attack_family is not None
        }
        if not self._records:
            raise ValueError("demo catalog contains no frozen test attacks")
        self.source_commit = source_commit

    @property
    def sample_count(self) -> int:
        return len(self._records)

    @classmethod
    def from_paths(
        cls,
        *,
        autodan_csv: Path,
        advprompter_csv: Path,
        gcg_csv: Path,
        expected_hashes: Mapping[str, str],
        source_commit: str,
    ) -> DemoSampleService:
        paths = {
            "autodan": autodan_csv,
            "advprompter": advprompter_csv,
            "gcg": gcg_csv,
        }
        if set(expected_hashes) != set(paths):
            raise ValueError("demo report must provide all source hashes")
        for source, path in paths.items():
            if not path.is_file() or _sha256(path) != expected_hashes[source]:
                raise ValueError(f"demo source checksum mismatch: {source}")

        records = _convert_unique(
            _read_csv(autodan_csv),
            CPDonlineAdapter("cpdonline/full_prompt_dataset"),
        )
        records.extend(
            _convert_unique(
                _read_csv(advprompter_csv),
                CPDonlineOptimizationAdapter(
                    "cpdonline/llama2_7b_foo_opt", "advprompter"
                ),
            )
        )
        records.extend(
            _convert_unique(
                _read_csv(gcg_csv),
                CPDonlineGuardBypassAdapter("cpdonline/gcg_guard_bypass"),
            )
        )
        if len({record.sample_id for record in records}) != len(records):
            raise ValueError("combined demo sources contain duplicate sample IDs")
        return cls(records=records, source_commit=source_commit)

    def list_samples(
        self, *, family: str | None, limit: int
    ) -> list[DemoSampleSummary]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        normalized_family = family.casefold() if family else None
        records = sorted(
            self._records.values(),
            key=lambda record: (
                record.attack_family.casefold() if record.attack_family else "",
                record.sample_id,
            ),
        )
        return [
            DemoSampleSummary(
                sample_id=record.sample_id,
                family=record.attack_family or "unknown",
            )
            for record in records
            if normalized_family is None
            or (record.attack_family or "").casefold() == normalized_family
        ][:limit]

    def analyze(self, sample_id: str, workflow: Any) -> DemoAnalysisResult:
        record = self._records.get(sample_id)
        if record is None:
            raise DemoSampleNotFound(sample_id)
        result = workflow.analyze(
            AnalysisRequest(
                prompt=record.prompt,
                model_id=workflow.calibration.model_id,
                mode="analysis",
            ),
            request_id=f"demo_{uuid.uuid4().hex}",
        )
        redacted_signals = [
            signal.model_copy(update={"token_id": 0, "token_text": ""})
            for signal in result.signals
        ]
        redacted_result = result.model_copy(
            update={"signals": redacted_signals, "audit_persisted": False}
        )
        return DemoAnalysisResult(
            sample_id=record.sample_id,
            family=record.attack_family or "unknown",
            dataset_commit=self.source_commit,
            result=redacted_result,
        )
