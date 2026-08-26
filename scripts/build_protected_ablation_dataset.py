from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from app.evaluation.ablation import EvaluationDomain
from app.evaluation.normalize import (
    CPDonlineAdapter,
    CPDonlineGuardBypassAdapter,
    CPDonlineOptimizationAdapter,
    PromptRecord,
    RowAdapter,
)
from scripts.collect_agent_ablation import ProtectedAblationRow


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _stable_source_id(prefix: str, value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{prefix} source ID must not be blank")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}_{digest}"


def _unique_records(
    rows: Iterable[Mapping[str, Any]], adapter: RowAdapter
) -> list[PromptRecord]:
    records: dict[str, PromptRecord] = {}
    for row in rows:
        record = adapter.convert(row)
        existing = records.get(record.sample_id)
        if existing is not None and existing != record:
            raise ValueError("source rows produced conflicting stable IDs")
        records[record.sample_id] = record
    return list(records.values())


def _cpdonline_row(record: PromptRecord) -> ProtectedAblationRow:
    if record.label_suffix_attack:
        if record.suffix_text is None or record.suffix_char_start is None:
            raise ValueError("optimized suffix record is missing suffix metadata")
        return ProtectedAblationRow(
            sample_id=record.sample_id,
            group_id=record.group_id,
            source_dataset=record.source_dataset,
            domain=EvaluationDomain.OPTIMIZED_SUFFIX,
            label_risky=True,
            attack_family=record.attack_family,
            suffix_start=record.suffix_char_start,
            suffix_end=len(record.prompt),
            prompt=record.prompt,
        )
    return ProtectedAblationRow(
        sample_id=record.sample_id,
        group_id=record.group_id,
        source_dataset=record.source_dataset,
        domain=EvaluationDomain.BENIGN_PLAIN,
        label_risky=False,
        prompt=record.prompt,
    )


def _harmbench_rows(
    rows: Iterable[Mapping[str, str]], excluded: Counter[str]
) -> list[ProtectedAblationRow]:
    normalized: list[ProtectedAblationRow] = []
    for row in rows:
        if str(row.get("FunctionalCategory", "")).strip().casefold() != "standard":
            excluded["harmbench_nonstandard"] += 1
            continue
        source_id = str(row.get("BehaviorID", ""))
        stable_id = _stable_source_id("harmbench", source_id)
        normalized.append(
            ProtectedAblationRow(
                sample_id=stable_id,
                group_id=stable_id,
                source_dataset="harmbench",
                domain=EvaluationDomain.SEMANTIC_UNSAFE,
                label_risky=True,
                prompt=str(row.get("Behavior", "")),
            )
        )
    return normalized


def _xstest_rows(
    rows: Iterable[Mapping[str, str]], excluded: Counter[str]
) -> list[ProtectedAblationRow]:
    normalized: list[ProtectedAblationRow] = []
    for row in rows:
        if str(row.get("label", "")).strip().casefold() != "safe":
            excluded["xstest_not_safe"] += 1
            continue
        source_id = str(row.get("id", ""))
        stable_id = _stable_source_id("xstest", source_id)
        group_id = _stable_source_id("xstest_group", str(row.get("type", "")))
        normalized.append(
            ProtectedAblationRow(
                sample_id=stable_id,
                group_id=group_id,
                source_dataset="xstest",
                domain=EvaluationDomain.BENIGN_SHIFT,
                label_risky=False,
                prompt=str(row.get("prompt", "")),
            )
        )
    return normalized


def _write_rows(path: Path, rows: list[ProtectedAblationRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="ascii", newline="\n") as stream:
        for row in sorted(rows, key=lambda item: item.sample_id):
            stream.write(
                json.dumps(
                    row.model_dump(mode="json"),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
    temporary.replace(path)


def build_protected_dataset(
    *,
    autodan_path: Path,
    advprompter_path: Path,
    gcg_path: Path,
    harmbench_path: Path,
    xstest_path: Path,
    output_path: Path,
) -> dict[str, object]:
    rows: list[ProtectedAblationRow] = []
    excluded: Counter[str] = Counter()
    cpdonline_sources = (
        (
            autodan_path,
            CPDonlineAdapter("cpdonline_autodan"),
        ),
        (
            advprompter_path,
            CPDonlineOptimizationAdapter(
                "cpdonline_advprompter", "advprompter"
            ),
        ),
        (
            gcg_path,
            CPDonlineGuardBypassAdapter("cpdonline_gcg"),
        ),
    )
    for path, adapter in cpdonline_sources:
        rows.extend(
            _cpdonline_row(record)
            for record in _unique_records(_read_csv(path), adapter)
        )
    rows.extend(_harmbench_rows(_read_csv(harmbench_path), excluded))
    rows.extend(_xstest_rows(_read_csv(xstest_path), excluded))

    identifiers = [row.sample_id for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("combined protected dataset contains duplicate sample IDs")
    domains = Counter(row.domain.value for row in rows)
    if set(domains) != {domain.value for domain in EvaluationDomain}:
        raise ValueError("protected dataset must contain all four evaluation domains")
    families = Counter(row.attack_family for row in rows if row.attack_family)
    _write_rows(output_path, rows)
    return {
        "total": len(rows),
        "domains": dict(sorted(domains.items())),
        "families": dict(sorted(families.items())),
        "excluded": dict(sorted(excluded.items())),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the protected four-domain agent ablation dataset"
    )
    parser.add_argument("--autodan-csv", type=Path, required=True)
    parser.add_argument("--advprompter-csv", type=Path, required=True)
    parser.add_argument("--gcg-csv", type=Path, required=True)
    parser.add_argument("--harmbench-csv", type=Path, required=True)
    parser.add_argument("--xstest-csv", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = build_protected_dataset(
        autodan_path=args.autodan_csv,
        advprompter_path=args.advprompter_csv,
        gcg_path=args.gcg_csv,
        harmbench_path=args.harmbench_csv,
        xstest_path=args.xstest_csv,
        output_path=args.output_jsonl,
    )
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
