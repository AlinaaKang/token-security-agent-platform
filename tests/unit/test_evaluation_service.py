from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.evaluation.ablation import SourceCoverageStatus
from app.evaluation.service import EvaluationReportService, UnsafeReportError
from tests.unit.test_ablation_cli import _manifest as write_ablation_manifest
from tests.unit.test_ablation_io import _report as ablation_report


def safe_report() -> dict:
    operating_point = {
        "threshold": 1.7,
        "precision": 0.8,
        "recall": 0.9,
        "f1": 0.847,
        "auroc": 0.75,
        "false_positive_rate": 0.1,
    }
    family = {
        "count": 2,
        "operating_points": {
            "f1_selected": {"detected": 2, "missed": 0, "recall": 1.0},
            "low_fpr_selected_on_dev": {
                "detected": 1,
                "missed": 1,
                "recall": 0.5,
            },
        },
        "score": {"min": 2.0, "median": 3.0, "max": 4.0},
    }
    methods = {}
    for method_id, display_name in (
        ("global_nll", "Global NLL"),
        ("window_nll", "Window NLL"),
        ("entropy_cpd", "Entropy-CPD"),
    ):
        methods[method_id] = {
            "display_name": display_name,
            "profile": {"threshold": 1.7},
            "operating_points": {
                "f1_selected": operating_point,
                "low_fpr_selected_on_dev": operating_point,
            },
            "families": {"autodan": family},
            "localization": (
                {"onset_mae": 2.0, "trigger_in_suffix_rate": 0.6}
                if method_id == "entropy_cpd"
                else None
            ),
            "latency_ms": {"p50_ms": 20.0, "p95_ms": 30.0},
        }
    return {
        "schema_version": 2,
        "counts": {"total": 3, "attacks": 2, "benign": 1},
        "methods": methods,
        "not_evaluated": ["autodan-hga", "beast"],
        "provenance": {
            "calibration_version": "cal-v1",
            "dataset_hash": "sha256:" + "a" * 64,
        },
    }


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")


def test_evaluation_service_loads_safe_report_and_marks_deployment_match() -> None:
    path = Path("tmp/test-evaluation-report.json")
    write_report(path, safe_report())
    try:
        summary = EvaluationReportService(path).load(
            active_calibration_version="cal-v1"
        )
    finally:
        path.unlink(missing_ok=True)

    assert summary.counts.total == 3
    assert set(summary.methods) == {"global_nll", "window_nll", "entropy_cpd"}
    assert summary.deployment_match is True


@pytest.mark.parametrize("forbidden_key", ["prompt", "suffix_text", "token_text"])
def test_evaluation_service_rejects_forbidden_fields_at_any_depth(
    forbidden_key: str,
) -> None:
    path = Path(f"tmp/test-unsafe-{forbidden_key}.json")
    report = safe_report()
    report["methods"]["entropy_cpd"]["families"]["autodan"][forbidden_key] = (
        "SAFE_PRIVATE_VALUE"
    )
    write_report(path, report)
    try:
        with pytest.raises(UnsafeReportError, match="forbidden field"):
            EvaluationReportService(path).load(active_calibration_version="cal-v1")
    finally:
        path.unlink(missing_ok=True)


def test_evaluation_service_marks_other_calibration_as_historical() -> None:
    path = Path("tmp/test-historical-evaluation.json")
    write_report(path, safe_report())
    try:
        summary = EvaluationReportService(path).load(
            active_calibration_version="cal-v2"
        )
    finally:
        path.unlink(missing_ok=True)

    assert summary.deployment_match is False


def test_evaluation_service_loads_optional_validated_agent_ablation() -> None:
    base_path = Path("tmp/test-evaluation-ablation-base.json")
    manifest_path = Path("tmp/test-evaluation-ablation-manifest.json")
    ablation_path = Path("tmp/test-evaluation-ablation-report.json")
    write_report(base_path, safe_report())
    write_ablation_manifest(manifest_path)
    report = ablation_report().model_copy(
        update={
            "source_coverage": {"safe-source": SourceCoverageStatus.VERIFIED},
            "coverage_gaps": (),
        }
    )
    ablation_path.write_text(report.model_dump_json(), encoding="ascii")
    try:
        service = EvaluationReportService(
            base_path,
            ablation_manifest_path=manifest_path,
            ablation_path=ablation_path,
        )
        summary = service.load(active_calibration_version="cal-v1")
    finally:
        base_path.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        ablation_path.unlink(missing_ok=True)

    assert summary.agent_ablation == report
    assert service.ablation_error_type is None


def test_invalid_agent_ablation_degrades_without_hiding_base_report() -> None:
    base_path = Path("tmp/test-evaluation-ablation-invalid-base.json")
    manifest_path = Path("tmp/test-evaluation-ablation-invalid-manifest.json")
    ablation_path = Path("tmp/test-evaluation-ablation-invalid-report.json")
    write_report(base_path, safe_report())
    write_ablation_manifest(manifest_path)
    payload = ablation_report().model_dump(mode="json")
    payload["prompt"] = "SAFE_PRIVATE_PROMPT"
    ablation_path.write_text(json.dumps(payload), encoding="ascii")
    try:
        service = EvaluationReportService(
            base_path,
            ablation_manifest_path=manifest_path,
            ablation_path=ablation_path,
        )
        summary = service.load(active_calibration_version="cal-v1")
    finally:
        base_path.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        ablation_path.unlink(missing_ok=True)

    assert summary.counts.total == 3
    assert summary.agent_ablation is None
    assert service.ablation_error_type is not None
