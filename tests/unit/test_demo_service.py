from __future__ import annotations

from app.demo.service import DemoSampleNotFound, DemoSampleService
from app.evaluation.normalize import PromptRecord
from app.evaluation.split import split_by_group
from app.lab.models import CounterfactualResult, CounterfactualSnapshot
from app.schemas import AnalysisResult, Provenance, TokenSignal


def make_records() -> list[PromptRecord]:
    records = []
    for index in range(30):
        suffix = f" SAFE_PATTERN_{index}"
        records.append(
            PromptRecord(
                sample_id=f"attack-{index:02d}",
                prompt=f"SAFE_BASE_{index}{suffix}",
                label_suffix_attack=True,
                attack_family="autodan" if index % 2 else "gcg",
                suffix_text=suffix,
                suffix_char_start=len(f"SAFE_BASE_{index}"),
                source_dataset="synthetic-safe",
                group_id=f"attack-group-{index:02d}",
            )
        )
    records.append(
        PromptRecord(
            sample_id="benign-00",
            prompt="SAFE_BENIGN_TEXT",
            label_suffix_attack=False,
            source_dataset="synthetic-safe",
            group_id="benign-group-00",
        )
    )
    return records


class StubWorkflow:
    class Calibration:
        model_id = "qwen-model"

    calibration = Calibration()

    def analyze(self, payload, *, request_id: str) -> AnalysisResult:
        return AnalysisResult(
            request_id=request_id,
            decision="block",
            risk_score=1.0,
            detector_score=5.0,
            detector_status="token_anomaly_candidate",
            semantic_severity="unsafe",
            semantic_categories=["jailbreak"],
            semantic_model_id="guard-model",
            semantic_model_version="guard-v1",
            semantic_latency_ms=2.0,
            semantic_verification="performed",
            fusion_reason="semantic_unsafe",
            signals=[
                TokenSignal(
                    index=0,
                    token_id=42,
                    token_text="SAFE_TOKEN_TEXT",
                    entropy=2.0,
                    nll=3.0,
                    cpd_entropy=5.0,
                    cpd_nll=0.0,
                    risk=1.0,
                )
            ],
            evidence=[],
            actions=["block"],
            provenance=Provenance(
                model_id="qwen-model",
                tokenizer_id="qwen-model",
                system_prompt_hash="sha256:system",
                calibration_version="cal-v1",
                thresholds={"k": 0.0, "h": 1.7},
            ),
            latency_ms=5.0,
        )


class RecordingCounterfactualRunner:
    def __init__(self) -> None:
        self.seen_prompt: str | None = None

    def run(self, *, prompt: str, original: AnalysisResult, mode: str):
        self.seen_prompt = prompt
        snapshot = CounterfactualSnapshot(
            semantic_severity=original.semantic_severity,
            detector_status=original.detector_status,
            risk_score=original.risk_score,
            detector_score=original.detector_score,
            decision=original.decision,
            latency_ms=original.latency_ms,
        )
        return CounterfactualResult(
            interpretation="inconclusive",
            reason="no_predicted_onset",
            calibration_version=original.provenance.calibration_version,
            original=snapshot,
        )


def test_demo_service_exposes_only_test_attacks_and_redacts_tokens() -> None:
    records = make_records()
    expected_test_ids = {
        record.sample_id
        for record in split_by_group(records, seed="competition-v1").test
        if record.label_suffix_attack
    }
    service = DemoSampleService(
        records=records,
        source_commit="safe-source-commit",
    )

    catalog = service.list_samples(family=None, limit=100)
    selected = catalog[0]
    analysis = service.analyze(selected.sample_id, StubWorkflow())

    assert {sample.sample_id for sample in catalog} == expected_test_ids
    assert all(sample.split == "test" for sample in catalog)
    assert analysis.result.signals[0].token_text == ""
    assert analysis.result.signals[0].token_id == 0
    assert analysis.result.semantic_severity == "unsafe"
    assert analysis.result.semantic_categories == ["jailbreak"]
    assert analysis.result.fusion_reason == "semantic_unsafe"
    assert analysis.result.audit_persisted is False


def test_demo_service_rejects_benign_and_non_test_ids() -> None:
    records = make_records()
    service = DemoSampleService(records=records, source_commit="safe-source-commit")
    test_ids = {
        record.sample_id
        for record in split_by_group(records, seed="competition-v1").test
    }
    non_test_attack = next(
        record.sample_id
        for record in records
        if record.label_suffix_attack and record.sample_id not in test_ids
    )

    for sample_id in ("benign-00", non_test_attack, "unknown-id"):
        try:
            service.analyze(sample_id, StubWorkflow())
        except DemoSampleNotFound:
            pass
        else:
            raise AssertionError(f"demo service accepted unavailable ID: {sample_id}")


def test_demo_lab_adapter_keeps_protected_text_inside_the_demo_boundary() -> None:
    service = DemoSampleService(
        records=make_records(), source_commit="safe-source-commit"
    )
    selected = service.list_samples(family=None, limit=1)[0]
    runner = RecordingCounterfactualRunner()

    family, analysis, counterfactual = service.analyze_for_lab(
        selected.sample_id,
        StubWorkflow(),
        mode="gateway",
        counterfactual_runner=runner,
    )

    assert family in {"gcg", "autodan"}
    assert runner.seen_prompt is not None
    assert runner.seen_prompt.startswith("SAFE_BASE_")
    assert analysis.signals[0].token_id == 0
    assert analysis.signals[0].token_text == ""
    serialized = analysis.model_dump_json() + counterfactual.model_dump_json()
    assert "SAFE_BASE_" not in serialized
    assert "SAFE_PATTERN_" not in serialized
    assert "SAFE_TOKEN_TEXT" not in serialized
