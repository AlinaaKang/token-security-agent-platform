from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Literal

from app.evaluation.grounded_report import (
    CANDIDATE_REPORT_CONFIGS,
    ExperimentPhase,
    ReportEvaluationSample,
    ReportExperimentConfig,
    ReportExperimentReport,
    SELECTION_RULE,
    SelectedReportConfig,
    assert_disjoint_sample_ids,
    build_experiment_report,
    evaluate_report_config,
    load_selected_report_config,
    select_report_config,
)
from app.evaluation.normalize import (
    CPDonlineAdapter,
    CPDonlineGuardBypassAdapter,
    CPDonlineOptimizationAdapter,
    PromptRecord,
    RowAdapter,
)
from app.knowledge.loader import load_knowledge_snapshot
from app.model.runtime import TransformersModelRuntime


FAMILIES = ("gcg", "autodan", "advprompter")
FORBIDDEN_AGGREGATE_KEYS = {
    "prompt",
    "suffix",
    "token",
    "token_text",
    "sample_id",
    "sample_ids",
    "raw_output",
    "raw_model_output",
    "grounded_report",
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _unique_records(path: Path, adapter: RowAdapter) -> list[PromptRecord]:
    records: dict[str, PromptRecord] = {}
    for row in _read_csv(path):
        record = adapter.convert(row)
        existing = records.get(record.sample_id)
        if existing is not None and existing != record:
            raise ValueError("protected source produced conflicting sample IDs")
        records[record.sample_id] = record
    return list(records.values())


def load_report_samples(
    *,
    autodan_csv: Path,
    advprompter_csv: Path,
    gcg_csv: Path,
) -> list[ReportEvaluationSample]:
    sources = (
        (
            autodan_csv,
            CPDonlineAdapter("cpdonline/full_prompt_dataset"),
        ),
        (
            advprompter_csv,
            CPDonlineOptimizationAdapter(
                "cpdonline/llama2_7b_foo_opt", "advprompter"
            ),
        ),
        (
            gcg_csv,
            CPDonlineGuardBypassAdapter("cpdonline/gcg_guard_bypass"),
        ),
    )
    samples: list[ReportEvaluationSample] = []
    for path, adapter in sources:
        for record in _unique_records(path, adapter):
            if (
                not record.label_suffix_attack
                or record.attack_family is None
                or record.suffix_char_start is None
            ):
                continue
            family = record.attack_family.casefold()
            if family not in FAMILIES:
                continue
            samples.append(
                ReportEvaluationSample(
                    sample_id=record.sample_id,
                    family=family,
                    prompt=record.prompt,
                    suffix_char_start=record.suffix_char_start,
                )
            )
    identifiers = [sample.sample_id for sample in samples]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("combined protected sources contain duplicate sample IDs")
    return samples


def _selection_key(sample: ReportEvaluationSample) -> bytes:
    payload = f"advanced-v2:{sample.family}:{sample.sample_id}".encode("utf-8")
    return hashlib.sha256(payload).digest()


def select_phase_samples(
    samples: list[ReportEvaluationSample], phase: ExperimentPhase
) -> list[ReportEvaluationSample]:
    selected: list[ReportEvaluationSample] = []
    for family in FAMILIES:
        ordered = sorted(
            (sample for sample in samples if sample.family == family),
            key=_selection_key,
        )
        if len(ordered) < 15:
            raise ValueError(
                "each protected family requires at least 15 unique samples"
            )
        selected.extend(ordered[:5] if phase == "development" else ordered[5:15])
    return selected


def _collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(key).casefold() for key in value} | {
            key for item in value.values() for key in _collect_keys(item)
        }
    if isinstance(value, (list, tuple)):
        return {key for item in value for key in _collect_keys(item)}
    return set()


def _aggregate_json(
    value: ReportExperimentReport | SelectedReportConfig,
    *,
    samples: list[ReportEvaluationSample],
) -> str:
    payload = value.model_dump(mode="json")
    forbidden = _collect_keys(payload).intersection(FORBIDDEN_AGGREGATE_KEYS)
    if forbidden:
        raise ValueError("aggregate output contains a forbidden field")
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    sensitive_values = (
        item
        for sample in samples
        for item in (sample.sample_id, sample.prompt)
        if len(item) >= 8
    )
    if any(item in serialized for item in sensitive_values):
        raise ValueError("aggregate output contains a protected value")
    return serialized + "\n"


def _write_aggregate(
    path: Path,
    value: ReportExperimentReport | SelectedReportConfig,
    *,
    samples: list[ReportEvaluationSample],
) -> None:
    serialized = _aggregate_json(value, samples=samples)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(serialized, encoding="ascii", newline="\n")
    temporary.replace(path)


def _runtime_version(runtime: object, model_path: str) -> str:
    readiness_method = getattr(runtime, "readiness", None)
    if callable(readiness_method):
        readiness = readiness_method()
        model_id = getattr(readiness, "model_id", None)
        if isinstance(model_id, str) and model_id.strip():
            return Path(model_id).name or model_id
    return Path(model_path).name or model_path


def _validate_development_aggregate(
    path: Path,
    *,
    selected: SelectedReportConfig,
    snapshot_hash: str,
) -> None:
    if not path.is_file():
        raise FileNotFoundError("development aggregate is required for frozen test")
    report = ReportExperimentReport.model_validate_json(
        path.read_text(encoding="ascii")
    )
    if report.phase != "development":
        raise ValueError("development aggregate has the wrong phase")
    if report.snapshot_version != selected.snapshot_version:
        raise ValueError("development aggregate snapshot version mismatch")
    if report.snapshot_hash != snapshot_hash:
        raise ValueError("development aggregate snapshot hash mismatch")
    if {result.config for result in report.candidate_results} != set(
        CANDIDATE_REPORT_CONFIGS
    ):
        raise ValueError("development aggregate candidate grid mismatch")
    expected_families = {"advprompter": 5, "autodan": 5, "gcg": 5}
    if any(
        result.metrics.total_count != 15
        or result.metrics.family_counts != expected_families
        for result in report.candidate_results
    ):
        raise ValueError("development aggregate family distribution mismatch")
    if select_report_config(report.candidate_results) != report.selected_config:
        raise ValueError("development aggregate mechanical winner mismatch")
    if report.selected_config != selected.experiment_config:
        raise ValueError("selected config does not match development aggregate")


def run_experiment(
    *,
    phase: ExperimentPhase,
    autodan_csv: Path,
    advprompter_csv: Path,
    gcg_csv: Path,
    snapshot_path: Path,
    output_path: Path,
    selected_config_path: Path,
    development_report_path: Path,
    model_path: str,
    runtime_factory: Callable[..., Any] = TransformersModelRuntime,
) -> ReportExperimentReport:
    if (
        phase == "development"
        and output_path.resolve() == selected_config_path.resolve()
    ):
        raise ValueError(
            "development output and selected config paths must be distinct"
        )
    if output_path.exists():
        raise FileExistsError("experiment output already exists")
    if phase == "test":
        selected_file = load_selected_report_config(selected_config_path)
        if not development_report_path.is_file():
            raise FileNotFoundError(
                "development aggregate is required for frozen test"
            )
    else:
        selected_file = None
        if selected_config_path.exists():
            raise FileExistsError("selected report config already exists")

    all_samples = load_report_samples(
        autodan_csv=autodan_csv,
        advprompter_csv=advprompter_csv,
        gcg_csv=gcg_csv,
    )
    development_samples = select_phase_samples(all_samples, "development")
    frozen_samples = select_phase_samples(all_samples, "test")
    assert_disjoint_sample_ids(
        (sample.sample_id for sample in development_samples),
        (sample.sample_id for sample in frozen_samples),
    )
    samples = development_samples if phase == "development" else frozen_samples
    snapshot = load_knowledge_snapshot(snapshot_path)
    if snapshot.manifest.snapshot_version != "official-v2":
        raise ValueError("report experiment requires official-v2")
    if selected_file is not None and (
        selected_file.snapshot_version != snapshot.manifest.snapshot_version
    ):
        raise ValueError("selected report config snapshot version mismatch")
    if selected_file is not None:
        _validate_development_aggregate(
            development_report_path,
            selected=selected_file,
            snapshot_hash=snapshot.manifest.cards_sha256,
        )

    runtime = runtime_factory(model_id=model_path, max_input_tokens=4096)
    load_runtime = getattr(runtime, "load", None)
    if callable(load_runtime):
        load_runtime()
    configurations = (
        CANDIDATE_REPORT_CONFIGS
        if phase == "development"
        else (selected_file.experiment_config,)  # type: ignore[union-attr]
    )
    results = tuple(
        evaluate_report_config(
            samples,
            snapshot=snapshot,
            runtime=runtime,
            config=config,
        )
        for config in configurations
    )
    selected_config = (
        select_report_config(results)
        if phase == "development"
        else configurations[0]
    )
    report = build_experiment_report(
        phase=phase,
        snapshot=snapshot,
        model_version=_runtime_version(runtime, model_path),
        candidate_results=results,
        selected_config=selected_config,
    )
    _write_aggregate(output_path, report, samples=samples)
    if phase == "development":
        _write_aggregate(
            selected_config_path,
            SelectedReportConfig(
                snapshot_version=snapshot.manifest.snapshot_version,
                max_new_tokens=selected_config.max_new_tokens,
                timeout_seconds=selected_config.timeout_seconds,
                selection_rule=SELECTION_RULE,
            ),
            samples=samples,
        )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the aggregate-only grounded report experiment"
    )
    parser.add_argument("--phase", choices=("development", "test"), required=True)
    parser.add_argument("--autodan-csv", type=Path, required=True)
    parser.add_argument("--advprompter-csv", type=Path, required=True)
    parser.add_argument("--gcg-csv", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--selected-config", type=Path, required=True)
    parser.add_argument(
        "--development-report",
        type=Path,
        default=Path("data/report-generation-development-report-v2.json"),
    )
    parser.add_argument("--model-path", required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = run_experiment(
        phase=args.phase,
        autodan_csv=args.autodan_csv,
        advprompter_csv=args.advprompter_csv,
        gcg_csv=args.gcg_csv,
        snapshot_path=args.snapshot,
        output_path=args.output,
        selected_config_path=args.selected_config,
        development_report_path=args.development_report,
        model_path=args.model_path,
    )
    metrics = report.metrics
    print(
        "grounded report experiment completed "
        f"phase={report.phase} total={metrics.total_count} "
        f"generated_rate={metrics.generated_rate:.6f} "
        f"citation_validity={metrics.citation_validity:.6f} "
        f"action_invariance={metrics.action_invariance:.6f} "
        f"latency_p95_ms={metrics.latency_p95_ms:.3f}"
    )


if __name__ == "__main__":
    main()
