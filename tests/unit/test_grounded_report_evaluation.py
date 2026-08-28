from __future__ import annotations

import json
from pathlib import Path

import pytest

import app.evaluation.grounded_report as grounded_report
from app.evaluation.grounded_report import (
    CANDIDATE_REPORT_CONFIGS,
    ReportConfigResult,
    ReportEvaluationSample,
    ReportExperimentConfig,
    ReportExperimentMetrics,
    assert_disjoint_sample_ids,
    build_experiment_report,
    evaluate_report_config,
    select_report_config,
)
from app.knowledge.loader import load_knowledge_snapshot


class FakeStructuredRuntime:
    def __init__(self) -> None:
        self.calls = 0
        self.serialized_messages: list[str] = []

    def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        max_new_tokens: int,
        max_time_seconds: float,
    ) -> str:
        self.calls += 1
        self.serialized_messages.append(json.dumps(messages, ensure_ascii=False))
        if self.calls == 2:
            raise TimeoutError
        payload = json.loads(messages[1]["content"])
        knowledge_id = payload["evidence"][0]["knowledge_id"]
        return json.dumps(
            {
                "summary": "aggregate-safe",
                "evidence_ids": [knowledge_id],
                "handling_steps": ["review"],
                "limitations": ["local evidence only"],
            }
        )


class MillisecondClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 0.001
        return self.value


def _metrics(
    *,
    generated_rate: float,
    citation_validity: float,
    latency_p95_ms: float,
) -> ReportExperimentMetrics:
    generated = round(generated_rate * 10)
    return ReportExperimentMetrics(
        total_count=10,
        generated_count=generated,
        fallback_count=10 - generated,
        generated_rate=generated_rate,
        citation_validity=citation_validity,
        action_invariance=1.0,
        latency_p50_ms=latency_p95_ms,
        latency_p95_ms=latency_p95_ms,
        failure_counts={
            "runtime_timeout": 10 - generated,
            "runtime_error": 0,
            "invalid_report_json": 0,
            "invalid_report_schema": 0,
            "invalid_report_citation": 0,
        },
        family_counts={"gcg": 10},
    )


def test_candidate_grid_is_the_frozen_nine_pairs() -> None:
    assert {
        (item.max_new_tokens, item.timeout_seconds)
        for item in CANDIDATE_REPORT_CONFIGS
    } == {
        (64, 3.0),
        (64, 5.0),
        (64, 6.0),
        (96, 3.0),
        (96, 5.0),
        (96, 6.0),
        (128, 3.0),
        (128, 5.0),
        (128, 6.0),
    }


def test_evaluator_measures_generated_fallback_citations_and_invariance() -> None:
    private_markers = ("PRIVATE_PROMPT", "PRIVATE_SUFFIX", "private-sample")
    samples = [
        ReportEvaluationSample(
            sample_id=f"private-sample-{index}",
            family="gcg",
            prompt=f"PRIVATE_PROMPT_{index} PRIVATE_SUFFIX_{index}",
            suffix_char_start=len(f"PRIVATE_PROMPT_{index}"),
        )
        for index in range(3)
    ]
    runtime = FakeStructuredRuntime()

    result = evaluate_report_config(
        samples,
        snapshot=load_knowledge_snapshot(
            Path("knowledge/snapshots/official-v2")
        ),
        runtime=runtime,
        config=ReportExperimentConfig(max_new_tokens=64, timeout_seconds=3.0),
        clock=MillisecondClock(),
    )

    assert result.metrics.generated_count == 2
    assert result.metrics.fallback_count == 1
    assert result.metrics.generated_rate == 2 / 3
    assert result.metrics.citation_validity == 1.0
    assert result.metrics.action_invariance == 1.0
    assert result.metrics.latency_p50_ms == pytest.approx(1.0)
    assert result.metrics.latency_p95_ms == pytest.approx(1.0)
    assert result.metrics.failure_counts == {
        "runtime_timeout": 1,
        "runtime_error": 0,
        "invalid_report_json": 0,
        "invalid_report_schema": 0,
        "invalid_report_citation": 0,
    }
    assert result.metrics.family_counts == {"gcg": 3}
    serialized = result.model_dump_json()
    assert all(marker not in serialized for marker in private_markers)
    assert all(
        marker not in message
        for marker in private_markers
        for message in runtime.serialized_messages
    )


def test_action_invariance_observes_the_production_enhancement_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = ReportEvaluationSample(
        sample_id="private-sample",
        family="gcg",
        prompt="PRIVATE_PROMPT PRIVATE_SUFFIX",
        suffix_char_start=len("PRIVATE_PROMPT"),
    )
    production_merge = grounded_report.merge_knowledge_enhancement

    def rewrite_decision(result, enhancement):
        return production_merge(result, enhancement).model_copy(
            update={"decision": "allow"}
        )

    monkeypatch.setattr(
        grounded_report,
        "merge_knowledge_enhancement",
        rewrite_decision,
        raising=False,
    )

    result = evaluate_report_config(
        [sample],
        snapshot=load_knowledge_snapshot(
            Path("knowledge/snapshots/official-v2")
        ),
        runtime=FakeStructuredRuntime(),
        config=ReportExperimentConfig(max_new_tokens=64, timeout_seconds=3.0),
        clock=MillisecondClock(),
    )

    assert result.metrics.action_invariance == 0.0


@pytest.mark.parametrize(
    ("left_config", "left_metrics", "right_config", "right_metrics", "expected"),
    [
        ((128, 6.0), (1.0, 1.0, 5001.0), (64, 3.0), (0.8, 0.9, 5000.0), (64, 3.0)),
        ((64, 3.0), (0.8, 1.0, 4000.0), (128, 6.0), (0.9, 0.9, 4999.0), (128, 6.0)),
        ((64, 3.0), (0.9, 0.9, 4000.0), (128, 6.0), (0.9, 1.0, 4999.0), (128, 6.0)),
        ((64, 3.0), (0.9, 1.0, 4000.0), (128, 6.0), (0.9, 1.0, 3999.0), (128, 6.0)),
        ((64, 6.0), (0.9, 1.0, 4000.0), (96, 3.0), (0.9, 1.0, 4000.0), (64, 6.0)),
        ((64, 3.0), (0.9, 1.0, 4000.0), (64, 5.0), (0.9, 1.0, 4000.0), (64, 3.0)),
    ],
)
def test_selector_uses_the_exact_mechanical_priority(
    left_config: tuple[int, float],
    left_metrics: tuple[float, float, float],
    right_config: tuple[int, float],
    right_metrics: tuple[float, float, float],
    expected: tuple[int, float],
) -> None:
    results = [
        ReportConfigResult(
            config=ReportExperimentConfig(
                max_new_tokens=left_config[0], timeout_seconds=left_config[1]
            ),
            metrics=_metrics(
                generated_rate=left_metrics[0],
                citation_validity=left_metrics[1],
                latency_p95_ms=left_metrics[2],
            ),
        ),
        ReportConfigResult(
            config=ReportExperimentConfig(
                max_new_tokens=right_config[0], timeout_seconds=right_config[1]
            ),
            metrics=_metrics(
                generated_rate=right_metrics[0],
                citation_validity=right_metrics[1],
                latency_p95_ms=right_metrics[2],
            ),
        ),
    ]

    selected = select_report_config(results)

    assert (selected.max_new_tokens, selected.timeout_seconds) == expected


def test_development_and_test_sample_ids_must_be_disjoint() -> None:
    assert_disjoint_sample_ids(["dev-a", "dev-b"], ["test-a", "test-b"])

    with pytest.raises(ValueError, match="overlap"):
        assert_disjoint_sample_ids(["same"], ["same"])


def test_historical_correction_marks_action_invariance_unverified() -> None:
    config_path = Path("data/report-generation-config-v2.json")
    development_path = Path("data/report-generation-development-report-v2.json")
    test_path = Path("data/report-generation-test-report-v2.json")
    original_bytes = {
        path: path.read_bytes()
        for path in (config_path, development_path, test_path)
    }

    correction = grounded_report.load_effective_report_summary(
        selected_config_path=config_path,
        development_report_path=development_path,
        test_report_path=test_path,
    )

    assert correction.action_invariance_evidence == "legacy_unverified"
    assert correction.target_status.action_invariance is False
    assert correction.checkpoint_identity_evidence == "legacy_unverified"
    assert correction.deadline_capability == "legacy_post_return_only"
    assert {
        path: path.read_bytes()
        for path in (config_path, development_path, test_path)
    } == original_bytes


def test_historical_correction_rejects_changed_source_artifact(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "selected.json"
    config_path.write_bytes(
        Path("data/report-generation-config-v2.json").read_bytes() + b" "
    )

    with pytest.raises(ValueError, match="artifact hash mismatch"):
        grounded_report.load_effective_report_summary(
            selected_config_path=config_path,
            development_report_path=Path(
                "data/report-generation-development-report-v2.json"
            ),
            test_report_path=Path("data/report-generation-test-report-v2.json"),
        )


def test_future_report_declares_deadline_capabilities() -> None:
    config = ReportExperimentConfig(max_new_tokens=64, timeout_seconds=5.0)
    result = ReportConfigResult(
        config=config,
        metrics=_metrics(
            generated_rate=1.0,
            citation_validity=1.0,
            latency_p95_ms=1000.0,
        ),
    )

    report = build_experiment_report(
        phase="test",
        snapshot=load_knowledge_snapshot(
            Path("knowledge/snapshots/official-v2")
        ),
        model_version="Qwen2.5-7B-Instruct",
        checkpoint_fingerprint="sha256:" + "1" * 64,
        candidate_results=[result],
        selected_config=config,
    )

    assert report.runtime_capabilities.model_dump() == {
        "deadline_enforcement": "cooperative_token_step",
        "stuck_cuda_kernel_termination": "cannot_terminate_in_process",
    }
