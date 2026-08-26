from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.bootstrap import DEFAULT_SYSTEM_PROMPT
from app.detection.calibration import CalibrationProfile
from app.detection.calibrator import (
    calibrate_entropy,
    select_candidate_by_dev,
    select_threshold_at_max_fpr,
)
from app.detection.cpd import run_cpd
from app.evaluation.normalize import (
    CPDonlineAdapter,
    CPDonlineGuardBypassAdapter,
    CPDonlineOptimizationAdapter,
    PromptRecord,
    RowAdapter,
)
from app.evaluation.methods import (
    MethodProfile,
    fit_global_nll,
    fit_window_nll,
    score_method,
)
from app.evaluation.reporting import (
    MethodReportInput,
    PromptPrediction,
    build_benchmark_report,
)
from app.evaluation.split import DatasetSplit, split_by_group, write_split_manifests
from app.model.runtime import ModelObservation, TransformersModelRuntime


class BenchmarkSampleError(RuntimeError):
    pass


def safe_exception_detail(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return ",".join(
            f"{'.'.join(str(part) for part in error['loc'])}:{error['type']}"
            for error in exc.errors(include_url=False, include_input=False)
        )
    return type(exc).__name__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a prompt-free CPDonline CPD benchmark."
    )
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--autodan-csv", type=Path, required=True)
    parser.add_argument("--advprompter-csv", type=Path, required=True)
    parser.add_argument("--gcg-csv", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--max-input-tokens", type=int, default=4096)
    return parser


def validate_input_paths(args: argparse.Namespace) -> None:
    for field_name in ("autodan_csv", "advprompter_csv", "gcg_csv"):
        path = getattr(args, field_name)
        if not path.is_file():
            raise FileNotFoundError(f"{field_name} is not a file: {path}")


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def normalize_unique_rows(
    rows: Iterable[Mapping[str, Any]], adapter: RowAdapter
) -> tuple[list[PromptRecord], int]:
    records_by_id: dict[str, PromptRecord] = {}
    duplicate_count = 0
    for row in rows:
        record = adapter.convert(row)
        existing = records_by_id.get(record.sample_id)
        if existing is None:
            records_by_id[record.sample_id] = record
        elif existing == record:
            duplicate_count += 1
        else:
            raise ValueError(
                f"sample ID collision has conflicting canonical records: "
                f"{record.sample_id}"
            )
    return list(records_by_id.values()), duplicate_count


def load_records(
    args: argparse.Namespace,
) -> tuple[list[PromptRecord], dict[str, int]]:
    records, autodan_duplicates = normalize_unique_rows(
        _read_csv(args.autodan_csv),
        CPDonlineAdapter("cpdonline/full_prompt_dataset"),
    )
    advprompter_records, advprompter_duplicates = normalize_unique_rows(
        _read_csv(args.advprompter_csv),
        CPDonlineOptimizationAdapter(
            "cpdonline/llama2_7b_foo_opt",
            "advprompter",
        )
    )
    gcg_records, gcg_duplicates = normalize_unique_rows(
        _read_csv(args.gcg_csv),
        CPDonlineGuardBypassAdapter("cpdonline/gcg_guard_bypass"),
    )
    records.extend(advprompter_records)
    records.extend(gcg_records)
    sample_ids = [record.sample_id for record in records]
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("combined CPDonline records contain duplicate sample IDs")
    return records, {
        "autodan_and_benign": autodan_duplicates,
        "advprompter": advprompter_duplicates,
        "gcg": gcg_duplicates,
    }


def _observe_records(
    runtime: TransformersModelRuntime,
    records: Sequence[PromptRecord],
    *,
    phase: str,
) -> list[ModelObservation]:
    observations: list[ModelObservation] = []
    for record in records:
        try:
            observations.append(
                runtime.score_prompt(DEFAULT_SYSTEM_PROMPT, record.prompt)
            )
        except Exception as exc:
            raise BenchmarkSampleError(
                f"{phase} sample_id={record.sample_id} failed with "
                f"{safe_exception_detail(exc)}"
            ) from None
    return observations


def _scores(
    observations: Sequence[ModelObservation], profile: CalibrationProfile
) -> list[float]:
    return [
        run_cpd(
            [token.entropy for token in observation.user_tokens],
            profile.baseline,
            k=profile.k,
            h=math.inf,
        ).score
        for observation in observations
    ]


def _predictions(
    records: Sequence[PromptRecord],
    observations: Sequence[ModelObservation],
    profile: CalibrationProfile,
) -> list[PromptPrediction]:
    predictions: list[PromptPrediction] = []
    for record, observation in zip(records, observations, strict=True):
        trace = run_cpd(
            [token.entropy for token in observation.user_tokens],
            profile.baseline,
            k=profile.k,
            h=profile.h,
        )
        onset_char_start = None
        if trace.onset_index is not None:
            onset_char_start = observation.user_tokens[trace.onset_index].char_start
        predictions.append(
            PromptPrediction(
                sample_id=record.sample_id,
                score=trace.score,
                alarm_index=trace.alarm_index,
                onset_char_start=onset_char_start,
                latency_ms=observation.latency_ms,
            )
        )
    return predictions


def _baseline_predictions(
    records: Sequence[PromptRecord],
    observations: Sequence[ModelObservation],
    profile: MethodProfile,
) -> list[PromptPrediction]:
    return [
        PromptPrediction(
            sample_id=record.sample_id,
            score=score_method(profile, observation),
            latency_ms=observation.latency_ms,
        )
        for record, observation in zip(records, observations, strict=True)
    ]


def _dataset_hash(output_dir: Path) -> str:
    manifest = json.loads(
        (output_dir / "splits" / "calibration.json").read_text(encoding="utf-8")
    )
    return str(manifest["dataset_hash"])


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    validate_input_paths(args)
    if args.max_input_tokens < 2:
        raise ValueError("max_input_tokens must be at least 2")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    records, duplicate_counts = load_records(args)
    split: DatasetSplit = split_by_group(records, seed="competition-v1")
    write_split_manifests(args.output_dir / "splits", split, seed="competition-v1")
    dataset_hash = _dataset_hash(args.output_dir)

    runtime = TransformersModelRuntime(
        model_id=args.model_path,
        max_input_tokens=args.max_input_tokens,
    )
    runtime.load()
    system_reference = runtime.score_system_prompt(DEFAULT_SYSTEM_PROMPT)

    calibration_observations = _observe_records(
        runtime, split.calibration, phase="calibration"
    )
    calibration_observations = [
        observation.model_copy(
            update={"system_entropies": system_reference.entropies}
        )
        for observation in calibration_observations
    ]
    calibration_labels = [
        record.label_suffix_attack for record in split.calibration
    ]
    candidates = [
        calibrate_entropy(
            calibration_observations,
            calibration_labels,
            version=f"{args.version}-candidate-k{k}",
            dataset_hash=dataset_hash,
            k=k,
        )
        for k in (0.0, 0.5)
    ]

    development_observations = _observe_records(
        runtime, split.dev, phase="development"
    )
    development_labels = [record.label_suffix_attack for record in split.dev]
    selected = select_candidate_by_dev(
        candidates,
        development_observations,
        development_labels,
    ).model_copy(update={"version": args.version})
    development_scores = _scores(development_observations, selected)
    low_fpr_threshold = select_threshold_at_max_fpr(
        development_labels,
        development_scores,
        max_fpr=0.10,
    )
    global_nll_profile = fit_global_nll(
        calibration_observations=calibration_observations,
        calibration_labels=calibration_labels,
        development_observations=development_observations,
        development_labels=development_labels,
    )
    window_nll_profile = fit_window_nll(
        calibration_observations=calibration_observations,
        calibration_labels=calibration_labels,
        development_observations=development_observations,
        development_labels=development_labels,
    )

    (args.output_dir / "calibration.json").write_text(
        json.dumps(
            selected.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )

    test_observations = _observe_records(runtime, split.test, phase="test")
    cpd_predictions = _predictions(split.test, test_observations, selected)
    global_nll_predictions = _baseline_predictions(
        split.test, test_observations, global_nll_profile
    )
    window_nll_predictions = _baseline_predictions(
        split.test, test_observations, window_nll_profile
    )
    provenance = {
        "model_id": selected.model_id,
        "tokenizer_id": selected.tokenizer_id,
        "system_prompt_hash": selected.system_prompt_hash,
        "baseline_source": "system_prompt",
        "baseline_median": selected.baseline.median,
        "baseline_mad_scale": selected.baseline.mad_scale,
        "k": selected.k,
        "h": selected.h,
        "calibration_version": selected.version,
        "dataset_hash": dataset_hash,
        "split_seed": "competition-v1",
        "cpdonline_commit": args.source_commit,
        "source_files": {
            "autodan": _sha256(args.autodan_csv),
            "advprompter": _sha256(args.advprompter_csv),
            "gcg": _sha256(args.gcg_csv),
        },
        "deduplicated_records": duplicate_counts,
    }
    report = build_benchmark_report(
        records=split.test,
        methods={
            "global_nll": MethodReportInput(
                display_name="Global NLL",
                predictions=global_nll_predictions,
                threshold=global_nll_profile.threshold,
                low_fpr_threshold=global_nll_profile.low_fpr_threshold,
                profile=global_nll_profile.model_dump(mode="json"),
            ),
            "window_nll": MethodReportInput(
                display_name="Window NLL",
                predictions=window_nll_predictions,
                threshold=window_nll_profile.threshold,
                low_fpr_threshold=window_nll_profile.low_fpr_threshold,
                profile=window_nll_profile.model_dump(mode="json"),
            ),
            "entropy_cpd": MethodReportInput(
                display_name="Entropy-CPD",
                predictions=cpd_predictions,
                threshold=selected.h,
                low_fpr_threshold=low_fpr_threshold,
                profile={
                    "threshold": selected.h,
                    "low_fpr_threshold": low_fpr_threshold,
                    "k": selected.k,
                    "baseline_median": selected.baseline.median,
                    "baseline_mad_scale": selected.baseline.mad_scale,
                },
                include_localization=True,
            ),
        },
        provenance=provenance,
        expected_families=(
            "gcg",
            "advprompter",
            "autodan",
            "beast",
            "autodan-hga",
        ),
    )
    report_path = args.output_dir / "benchmark_report.json"
    report_path.write_text(
        json.dumps(
            report,
            ensure_ascii=True,
            indent=2,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "status": "completed",
        "calibration_path": str(args.output_dir / "calibration.json"),
        "report_path": str(report_path),
        "counts": report["counts"],
        "selected": {
            "entropy_cpd": {"k": selected.k, "h": selected.h},
            "global_nll": global_nll_profile.model_dump(mode="json"),
            "window_nll": window_nll_profile.model_dump(mode="json"),
        },
        "methods": {
            method_id: {
                "operating_points": method["operating_points"],
                "families": method["families"],
            }
            for method_id, method in report["methods"].items()
        },
        "not_evaluated": report["not_evaluated"],
    }


def main() -> None:
    args = build_parser().parse_args()
    try:
        summary = run_benchmark(args)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                },
                ensure_ascii=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    print(json.dumps(summary, ensure_ascii=True, allow_nan=False))


if __name__ == "__main__":
    main()
