from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from app.evaluation.ablation import EvaluationDomain, SourceCoverageStatus
from app.evaluation.ablation_io import (
    AblationBenchmarkManifest,
    AblationSplitManifest,
    SourceRevision,
    write_ascii_json,
)
from app.evaluation.normalize import PromptRecord
from app.evaluation.split import DatasetSplit, split_by_group
from scripts.collect_agent_ablation import ProtectedAblationRow, load_protected_rows


class SourceRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    sources: tuple[SourceRevision, ...]

    @model_validator(mode="after")
    def _unique_sources(self) -> "SourceRegistry":
        identifiers = [source.source_id for source in self.sources]
        if not identifiers or len(set(identifiers)) != len(identifiers):
            raise ValueError("source registry requires unique source IDs")
        return self


def _load_sources(path: Path) -> SourceRegistry:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return SourceRegistry.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError("source registry is invalid") from exc


def _dataset_hash(
    rows: tuple[ProtectedAblationRow, ...],
    sources: tuple[SourceRevision, ...],
    seed: str,
) -> str:
    identities = []
    for row in sorted(rows, key=lambda item: item.sample_id):
        identities.append(
            {
                "sample_id": row.sample_id,
                "group_id": row.group_id,
                "source_dataset": row.source_dataset,
                "domain": row.domain.value,
                "label_risky": row.label_risky,
                "attack_family": row.attack_family,
                "suffix_start": row.suffix_start,
                "suffix_end": row.suffix_end,
                "prompt_sha256": hashlib.sha256(row.prompt.encode("utf-8")).hexdigest(),
            }
        )
    payload = {
        "seed": seed,
        "records": identities,
        "sources": [
            source.model_dump(mode="json")
            for source in sorted(sources, key=lambda item: item.source_id)
        ],
    }
    serialized = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(serialized).hexdigest()


def _prompt_record(row: ProtectedAblationRow) -> PromptRecord:
    return PromptRecord(
        sample_id=row.sample_id,
        prompt=row.prompt,
        label_suffix_attack=row.domain is EvaluationDomain.OPTIMIZED_SUFFIX,
        label_semantic_unsafe=(
            row.domain is EvaluationDomain.SEMANTIC_UNSAFE
        ),
        attack_family=row.attack_family,
        suffix_text=(
            row.prompt[row.suffix_start : row.suffix_end]
            if row.suffix_start is not None and row.suffix_end is not None
            else None
        ),
        suffix_char_start=row.suffix_start,
        source_dataset=row.source_dataset,
        group_id=row.group_id,
    )


def _split_manifest(
    name: Literal["calibration", "dev", "test"],
    records: tuple[PromptRecord, ...],
    by_id: dict[str, ProtectedAblationRow],
) -> AblationSplitManifest:
    rows = [by_id[record.sample_id] for record in records]
    domains = Counter(row.domain for row in rows)
    families = Counter(
        row.attack_family for row in rows if row.attack_family is not None
    )
    return AblationSplitManifest(
        split=name,
        sample_ids=tuple(sorted(row.sample_id for row in rows)),
        group_ids=tuple(sorted({row.group_id for row in rows})),
        domain_counts=dict(sorted(domains.items(), key=lambda item: item[0].value)),
        family_counts=dict(sorted(families.items())),
    )


def _validate_coverage(rows: tuple[ProtectedAblationRow, ...]) -> None:
    domains = {row.domain for row in rows}
    if domains != set(EvaluationDomain):
        raise ValueError("protected benchmark must cover all four evaluation domains")
    family_groups: dict[str, set[str]] = {}
    for row in rows:
        if row.attack_family is not None:
            family_groups.setdefault(row.attack_family, set()).add(row.group_id)
    if any(len(groups) < 3 for groups in family_groups.values()):
        raise ValueError("each attack family requires at least three groups")


def _write_frozen_rows(
    path: Path,
    rows: tuple[ProtectedAblationRow, ...],
    manifest: AblationBenchmarkManifest,
) -> None:
    split_by_id = {
        sample_id: split.split
        for split in manifest.splits
        for sample_id in split.sample_ids
    }
    if set(split_by_id) != {row.sample_id for row in rows}:
        raise ValueError("manifest and protected rows have different sample IDs")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="ascii", newline="\n") as stream:
        for row in sorted(rows, key=lambda item: item.sample_id):
            frozen = row.model_copy(update={"split": split_by_id[row.sample_id]})
            stream.write(
                json.dumps(
                    frozen.model_dump(mode="json"),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
    temporary.replace(path)


def build_manifest(
    *,
    input_path: Path,
    sources_path: Path,
    output_path: Path,
    benchmark_version: str,
    seed: str,
    frozen_output_path: Path | None = None,
) -> AblationBenchmarkManifest:
    if not benchmark_version.strip() or not seed.strip():
        raise ValueError("benchmark version and split seed must not be blank")
    rows = load_protected_rows(input_path)
    registry = _load_sources(sources_path)
    sources_by_id = {source.source_id: source for source in registry.sources}
    for row in rows:
        source = sources_by_id.get(row.source_dataset)
        if source is None:
            raise ValueError("protected row references an unknown source")
        if source.status is not SourceCoverageStatus.VERIFIED:
            raise ValueError("protected row source is not verified")
    _validate_coverage(rows)

    records = [_prompt_record(row) for row in rows]
    split: DatasetSplit = split_by_group(records, seed=seed)
    by_id = {row.sample_id: row for row in rows}
    manifest = AblationBenchmarkManifest(
        benchmark_version=benchmark_version,
        dataset_hash=_dataset_hash(rows, registry.sources, seed),
        split_seed=seed,
        sources=tuple(sorted(registry.sources, key=lambda item: item.source_id)),
        splits=(
            _split_manifest("calibration", split.calibration, by_id),
            _split_manifest("dev", split.dev, by_id),
            _split_manifest("test", split.test, by_id),
        ),
    )
    write_ascii_json(output_path, manifest)
    if frozen_output_path is not None:
        _write_frozen_rows(frozen_output_path, rows, manifest)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a privacy-safe frozen agent ablation manifest"
    )
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--benchmark-version", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--frozen-output-jsonl", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    manifest = build_manifest(
        input_path=args.input_jsonl,
        sources_path=args.sources,
        output_path=args.output,
        benchmark_version=args.benchmark_version,
        seed=args.seed,
        frozen_output_path=args.frozen_output_jsonl,
    )
    print(
        "ablation manifest completed "
        f"version={manifest.benchmark_version} samples="
        f"{sum(len(split.sample_ids) for split in manifest.splits)}"
    )


if __name__ == "__main__":
    main()
