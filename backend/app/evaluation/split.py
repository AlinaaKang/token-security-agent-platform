from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.evaluation.normalize import DatasetValidationError, PromptRecord


class DatasetSplit(BaseModel):
    calibration: tuple[PromptRecord, ...]
    dev: tuple[PromptRecord, ...]
    test: tuple[PromptRecord, ...]


def _rank_group(group_id: str, seed: str) -> str:
    return hashlib.sha256(f"{seed}\x1f{group_id}".encode("utf-8")).hexdigest()


def split_by_group(records: list[PromptRecord], seed: str) -> DatasetSplit:
    if not seed:
        raise ValueError("seed must not be blank")

    grouped: dict[str, list[PromptRecord]] = defaultdict(list)
    for record in records:
        grouped[record.group_id].append(record)

    group_ids = sorted(grouped, key=lambda group_id: _rank_group(group_id, seed))
    if len(group_ids) < 3:
        raise DatasetValidationError("at least three groups are required for splitting")

    calibration_count = max(1, round(len(group_ids) * 0.2))
    dev_count = max(1, round(len(group_ids) * 0.2))
    if calibration_count + dev_count >= len(group_ids):
        dev_count = 1
        calibration_count = 1

    calibration_ids = set(group_ids[:calibration_count])
    dev_ids = set(group_ids[calibration_count : calibration_count + dev_count])

    calibration: list[PromptRecord] = []
    dev: list[PromptRecord] = []
    test: list[PromptRecord] = []
    for record in records:
        if record.group_id in calibration_ids:
            calibration.append(record)
        elif record.group_id in dev_ids:
            dev.append(record)
        else:
            test.append(record)

    return DatasetSplit(
        calibration=tuple(calibration),
        dev=tuple(dev),
        test=tuple(test),
    )


def _all_records(split: DatasetSplit) -> tuple[PromptRecord, ...]:
    return split.calibration + split.dev + split.test


def _dataset_hash(split: DatasetSplit) -> str:
    identities = sorted(
        f"{record.sample_id}\x1f{record.group_id}" for record in _all_records(split)
    )
    return "sha256:" + hashlib.sha256("\n".join(identities).encode("utf-8")).hexdigest()


def write_split_manifests(
    output_directory: str | Path, split: DatasetSplit, seed: str
) -> None:
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)
    dataset_hash = _dataset_hash(split)

    for name in ("calibration", "dev", "test"):
        records = getattr(split, name)
        manifest = {
            "schema_version": 1,
            "split": name,
            "seed": seed,
            "dataset_hash": dataset_hash,
            "sample_ids": [record.sample_id for record in records],
            "group_ids": sorted({record.group_id for record in records}),
        }
        (output_path / f"{name}.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def build_dataset_card(
    split: DatasetSplit,
    seed: str,
    attributions: list[dict[str, str]],
) -> dict[str, Any]:
    records = _all_records(split)
    attack_count = sum(record.label_suffix_attack for record in records)
    source_counts: dict[str, int] = defaultdict(int)
    for record in records:
        source_counts[record.source_dataset] += 1

    return {
        "schema_version": 1,
        "dataset_hash": _dataset_hash(split),
        "split_method": "sha256-ranked group-aware 20/20/60",
        "seed": seed,
        "counts": {
            "total": len(records),
            "calibration": len(split.calibration),
            "dev": len(split.dev),
            "test": len(split.test),
        },
        "labels": {
            "suffix_attack": attack_count,
            "benign": len(records) - attack_count,
        },
        "sources": dict(sorted(source_counts.items())),
        "attributions": [dict(attribution) for attribution in attributions],
        "contains_prompt_text": False,
    }
