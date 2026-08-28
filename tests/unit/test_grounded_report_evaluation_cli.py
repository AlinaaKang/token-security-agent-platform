from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NoReturn

import pytest

from scripts.evaluate_grounded_reports import (
    load_report_samples,
    run_experiment,
    select_phase_samples,
)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_sources(root: Path) -> tuple[Path, Path, Path]:
    autodan = root / "autodan.csv"
    advprompter = root / "advprompter.csv"
    gcg = root / "gcg.csv"
    _write_csv(
        autodan,
        ["full_prompt", "suffix", "is_adversarial", "algorithm"],
        [
            {
                "full_prompt": f"PRIVATE_AUTODAN_BASE_{index} PRIVATE_SUFFIX_{index}",
                "suffix": f" PRIVATE_SUFFIX_{index}",
                "is_adversarial": "True",
                "algorithm": "AutoDAN",
            }
            for index in range(15)
        ],
    )
    _write_csv(
        advprompter,
        ["instruct", "target", "suffix", "full_instruct"],
        [
            {
                "instruct": f"PRIVATE_ADVPROMPTER_BASE_{index}",
                "target": "PRIVATE_TARGET",
                "suffix": f" PRIVATE_SUFFIX_{index}",
                "full_instruct": (
                    f"PRIVATE_ADVPROMPTER_BASE_{index} PRIVATE_SUFFIX_{index}"
                ),
            }
            for index in range(15)
        ],
    )
    _write_csv(
        gcg,
        ["prompt", "target", "trigger"],
        [
            {
                "prompt": f"PRIVATE_GCG_BASE_{index}",
                "target": "PRIVATE_TARGET",
                "trigger": f" PRIVATE_SUFFIX_{index}",
            }
            for index in range(15)
        ],
    )
    return autodan, advprompter, gcg


def _selection_key(family: str, sample_id: str) -> str:
    return hashlib.sha256(
        f"advanced-v2:{family}:{sample_id}".encode("utf-8")
    ).hexdigest()


def _runtime_must_not_start(**_: object) -> NoReturn:
    raise AssertionError("frozen gate must reject before runtime startup")


class MismatchedModelRuntime:
    def __init__(self, **_: object) -> None:
        self.loaded = False

    def load(self) -> None:
        self.loaded = True

    def readiness(self) -> SimpleNamespace:
        return SimpleNamespace(ready=True, model_id="different-model")


class MissingModelIdentityRuntime:
    def __init__(self, **_: object) -> None:
        self.loaded = False

    def load(self) -> None:
        self.loaded = True


def _run_frozen_with_aggregate(
    tmp_path: Path,
    development_payload: dict[str, Any],
    selected_payload: dict[str, Any] | None = None,
) -> None:
    autodan, advprompter, gcg = _write_sources(tmp_path / "sources")
    development = tmp_path / "development.json"
    selected = tmp_path / "selected.json"
    development.write_text(json.dumps(development_payload), encoding="utf-8")
    selected.write_text(
        json.dumps(
            selected_payload
            or json.loads(
                Path("data/report-generation-config-v2.json").read_text(
                    encoding="ascii"
                )
            )
        ),
        encoding="utf-8",
    )
    run_experiment(
        phase="test",
        autodan_csv=autodan,
        advprompter_csv=advprompter,
        gcg_csv=gcg,
        snapshot_path=Path("knowledge/snapshots/official-v2"),
        output_path=tmp_path / "test-report.json",
        selected_config_path=selected,
        development_report_path=development,
        model_path="Qwen2.5-7B-Instruct",
        runtime_factory=_runtime_must_not_start,
    )


def test_split_uses_family_scoped_hash_order_and_never_overlaps(
    tmp_path: Path,
) -> None:
    autodan, advprompter, gcg = _write_sources(tmp_path)
    samples = load_report_samples(
        autodan_csv=autodan,
        advprompter_csv=advprompter,
        gcg_csv=gcg,
    )

    development = select_phase_samples(samples, "development")
    frozen = select_phase_samples(samples, "test")

    assert {family: sum(row.family == family for row in development) for family in ("autodan", "advprompter", "gcg")} == {
        "autodan": 5,
        "advprompter": 5,
        "gcg": 5,
    }
    assert {family: sum(row.family == family for row in frozen) for family in ("autodan", "advprompter", "gcg")} == {
        "autodan": 10,
        "advprompter": 10,
        "gcg": 10,
    }
    assert {row.sample_id for row in development}.isdisjoint(
        row.sample_id for row in frozen
    )
    for family in ("autodan", "advprompter", "gcg"):
        ordered = sorted(
            (row for row in samples if row.family == family),
            key=lambda row: _selection_key(family, row.sample_id),
        )
        assert [row.sample_id for row in development if row.family == family] == [
            row.sample_id for row in ordered[:5]
        ]
        assert [row.sample_id for row in frozen if row.family == family] == [
            row.sample_id for row in ordered[5:15]
        ]


def test_frozen_test_refuses_to_run_without_development_aggregate(
    tmp_path: Path,
) -> None:
    autodan, advprompter, gcg = _write_sources(tmp_path)
    config = tmp_path / "selected.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "snapshot_version": "official-v2",
                "max_new_tokens": 96,
                "timeout_seconds": 5.0,
                "selection_rule": (
                    "p95_budget_generated_rate_citation_latency_size"
                ),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(FileNotFoundError, match="development aggregate"):
        run_experiment(
            phase="test",
            autodan_csv=autodan,
            advprompter_csv=advprompter,
            gcg_csv=gcg,
            snapshot_path=Path("knowledge/snapshots/official-v2"),
            output_path=tmp_path / "test-report.json",
            selected_config_path=config,
            development_report_path=tmp_path / "missing-development.json",
            model_path="Qwen2.5-7B-Instruct",
        )


def test_development_rejects_colliding_aggregate_output_paths(
    tmp_path: Path,
) -> None:
    autodan, advprompter, gcg = _write_sources(tmp_path / "sources")
    aggregate_path = tmp_path / "aggregate.json"

    with pytest.raises(ValueError, match="must be distinct"):
        run_experiment(
            phase="development",
            autodan_csv=autodan,
            advprompter_csv=advprompter,
            gcg_csv=gcg,
            snapshot_path=Path("knowledge/snapshots/official-v2"),
            output_path=aggregate_path,
            selected_config_path=aggregate_path,
            development_report_path=tmp_path / "development.json",
            model_path="Qwen2.5-7B-Instruct",
            runtime_factory=_runtime_must_not_start,
        )


def test_frozen_gate_rejects_development_report_without_exact_grid(
    tmp_path: Path,
) -> None:
    payload = json.loads(
        Path("data/report-generation-development-report-v2.json").read_text(
            encoding="ascii"
        )
    )
    payload["candidate_results"][0] = payload["candidate_results"][2]

    with pytest.raises(ValueError, match="candidate grid"):
        _run_frozen_with_aggregate(tmp_path, payload)


def test_frozen_gate_rejects_non_mechanical_development_winner(
    tmp_path: Path,
) -> None:
    payload = json.loads(
        Path("data/report-generation-development-report-v2.json").read_text(
            encoding="ascii"
        )
    )
    non_winner = payload["candidate_results"][0]
    payload["selected_config"] = non_winner["config"]
    payload["metrics"] = non_winner["metrics"]
    selected = json.loads(
        Path("data/report-generation-config-v2.json").read_text(encoding="ascii")
    )
    selected.update(non_winner["config"])

    with pytest.raises(ValueError, match="mechanical winner"):
        _run_frozen_with_aggregate(tmp_path, payload, selected)


def test_frozen_gate_rejects_wrong_development_family_distribution(
    tmp_path: Path,
) -> None:
    payload = json.loads(
        Path("data/report-generation-development-report-v2.json").read_text(
            encoding="ascii"
        )
    )
    payload["candidate_results"][0]["metrics"]["family_counts"] = {"gcg": 15}

    with pytest.raises(ValueError, match="family distribution"):
        _run_frozen_with_aggregate(tmp_path, payload)


def test_frozen_gate_rejects_development_snapshot_hash_mismatch(
    tmp_path: Path,
) -> None:
    payload = json.loads(
        Path("data/report-generation-development-report-v2.json").read_text(
            encoding="ascii"
        )
    )
    payload["snapshot_hash"] = "sha256:" + "0" * 64

    with pytest.raises(ValueError, match="snapshot hash"):
        _run_frozen_with_aggregate(tmp_path, payload)


def test_frozen_gate_rejects_development_model_identity_mismatch(
    tmp_path: Path,
) -> None:
    payload = json.loads(
        Path("data/report-generation-development-report-v2.json").read_text(
            encoding="ascii"
        )
    )
    payload["model_version"] = "different-model"

    with pytest.raises(ValueError, match="model identity"):
        _run_frozen_with_aggregate(tmp_path, payload)


def test_frozen_gate_rejects_noncanonical_model_path_before_runtime(
    tmp_path: Path,
) -> None:
    autodan, advprompter, gcg = _write_sources(tmp_path / "sources")

    with pytest.raises(ValueError, match="model identity"):
        run_experiment(
            phase="test",
            autodan_csv=autodan,
            advprompter_csv=advprompter,
            gcg_csv=gcg,
            snapshot_path=Path("knowledge/snapshots/official-v2"),
            output_path=tmp_path / "test-report.json",
            selected_config_path=Path("data/report-generation-config-v2.json"),
            development_report_path=Path(
                "data/report-generation-development-report-v2.json"
            ),
            model_path="different-model",
            runtime_factory=_runtime_must_not_start,
        )


def test_frozen_gate_rejects_loaded_runtime_model_identity_mismatch(
    tmp_path: Path,
) -> None:
    autodan, advprompter, gcg = _write_sources(tmp_path / "sources")

    with pytest.raises(ValueError, match="model identity"):
        run_experiment(
            phase="test",
            autodan_csv=autodan,
            advprompter_csv=advprompter,
            gcg_csv=gcg,
            snapshot_path=Path("knowledge/snapshots/official-v2"),
            output_path=tmp_path / "test-report.json",
            selected_config_path=Path("data/report-generation-config-v2.json"),
            development_report_path=Path(
                "data/report-generation-development-report-v2.json"
            ),
            model_path="Qwen2.5-7B-Instruct",
            runtime_factory=MismatchedModelRuntime,
        )


def test_frozen_gate_rejects_runtime_without_loaded_model_identity(
    tmp_path: Path,
) -> None:
    autodan, advprompter, gcg = _write_sources(tmp_path / "sources")

    with pytest.raises(ValueError, match="model identity unavailable"):
        run_experiment(
            phase="test",
            autodan_csv=autodan,
            advprompter_csv=advprompter,
            gcg_csv=gcg,
            snapshot_path=Path("knowledge/snapshots/official-v2"),
            output_path=tmp_path / "test-report.json",
            selected_config_path=Path("data/report-generation-config-v2.json"),
            development_report_path=Path(
                "data/report-generation-development-report-v2.json"
            ),
            model_path="Qwen2.5-7B-Instruct",
            runtime_factory=MissingModelIdentityRuntime,
        )
