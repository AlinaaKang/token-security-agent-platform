from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.agent.fusion import FusionReason
from app.knowledge.loader import load_knowledge_snapshot
from app.knowledge.models import KnowledgeEvidence, NormalizedSecurityFacts
from app.knowledge.query import RetrievalQuery
from app.knowledge.reporting import (
    DeterministicReportComposer,
    GroundedReport,
    GroundedReportError,
    QwenGroundedReportGenerator,
    ReportGeneration,
    build_report_messages,
    parse_grounded_report,
)
from app.knowledge.retriever import LocalKnowledgeRetriever


VALID_REPORT = {
    "summary": "检测证据与知识依据一致。",
    "evidence_ids": ["owasp-llm01-prompt-injection"],
    "handling_steps": ["保留脱敏审计证据", "按既定动作处置"],
    "limitations": ["知识证据不改变基础判定"],
}


def _evidence() -> list[KnowledgeEvidence]:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v1"))
    return LocalKnowledgeRetriever(snapshot).search(
        RetrievalQuery(
            query_text="safe synthetic query",
            lexical_terms=("prompt", "injection"),
            routing_tags=("jailbreak", "cpd_candidate"),
            used_prefix_only=False,
        ),
        top_k=1,
    )


def _facts() -> NormalizedSecurityFacts:
    return NormalizedSecurityFacts(
        semantic_severity="unsafe",
        semantic_categories=("jailbreak",),
        detector_status="token_anomaly_candidate",
        anomaly_char_start=32,
        fusion_reason=FusionReason.SEMANTIC_UNSAFE,
        decision="block",
        mode="analysis",
        attack_family="AutoDAN",
    )


def test_parser_accepts_only_known_evidence_ids() -> None:
    report = parse_grounded_report(
        json.dumps(VALID_REPORT, ensure_ascii=False),
        allowed_ids={"owasp-llm01-prompt-injection"},
    )

    assert report.evidence_ids == ("owasp-llm01-prompt-injection",)
    assert report.handling_steps[0] == "保留脱敏审计证据"


@pytest.mark.parametrize(
    ("raw", "error_code"),
    [
        ("```json\n{}\n```", "invalid_report_json"),
        ("prefix " + json.dumps(VALID_REPORT), "invalid_report_json"),
        (json.dumps({**VALID_REPORT, "decision": "allow"}), "invalid_report_schema"),
        (json.dumps({**VALID_REPORT, "evidence_ids": []}), "invalid_report_schema"),
        (
            json.dumps({**VALID_REPORT, "evidence_ids": ["unknown-id"]}),
            "invalid_report_citation",
        ),
        (
            json.dumps(
                {
                    **VALID_REPORT,
                    "evidence_ids": [
                        "owasp-llm01-prompt-injection",
                        "owasp-llm01-prompt-injection",
                    ],
                }
            ),
            "invalid_report_schema",
        ),
    ],
)
def test_parser_rejects_untrusted_or_ungrounded_output(
    raw: str,
    error_code: str,
) -> None:
    with pytest.raises(GroundedReportError) as captured:
        parse_grounded_report(
            raw,
            allowed_ids={"owasp-llm01-prompt-injection"},
        )

    assert str(captured.value) == error_code
    assert raw not in repr(captured.value)


def test_deterministic_composer_references_only_retrieved_evidence() -> None:
    evidence = _evidence()

    report = DeterministicReportComposer().compose(_facts(), evidence)

    assert report.evidence_ids == tuple(item.knowledge_id for item in evidence)
    assert report.handling_steps == evidence[0].recommendations
    assert report.limitations == ("知识证据不改变基础检测动作。",)


class FakeStructuredRuntime:
    def __init__(self, raw: str | Exception) -> None:
        self.raw = raw
        self.messages: list[dict[str, str]] | None = None
        self.options: tuple[int, float] | None = None

    def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        max_new_tokens: int,
        max_time_seconds: float,
    ) -> str:
        self.messages = messages
        self.options = (max_new_tokens, max_time_seconds)
        if isinstance(self.raw, Exception):
            raise self.raw
        return self.raw


def test_qwen_generator_returns_generated_report_for_valid_citations() -> None:
    evidence = _evidence()
    payload = {**VALID_REPORT, "evidence_ids": [evidence[0].knowledge_id]}
    runtime = FakeStructuredRuntime(json.dumps(payload, ensure_ascii=False))

    generation = QwenGroundedReportGenerator(runtime).generate(_facts(), evidence)

    assert generation.status == "generated"
    assert generation.failure_code is None
    assert generation.report.evidence_ids == (evidence[0].knowledge_id,)
    assert runtime.options == (256, 3.0)
    serialized_messages = json.dumps(runtime.messages, ensure_ascii=False)
    assert "SAFE_PRIVATE_QUERY" not in serialized_messages
    assert "query_text" not in serialized_messages


def test_qwen_generator_rejects_empty_evidence_before_runtime_invocation() -> None:
    runtime = FakeStructuredRuntime(TimeoutError("SAFE_PRIVATE_TIMEOUT"))

    with pytest.raises(
        ValueError,
        match="^grounded report requires at least one retrieved evidence item$",
    ):
        QwenGroundedReportGenerator(runtime).generate(_facts(), [])

    assert runtime.messages is None


@pytest.mark.parametrize(
    ("status", "failure_code"),
    [
        ("generated", "runtime_error"),
        ("fallback", None),
    ],
)
def test_report_generation_rejects_inconsistent_status_and_failure_code(
    status: str,
    failure_code: str | None,
) -> None:
    with pytest.raises(ValidationError):
        ReportGeneration(
            report=GroundedReport.model_validate(VALID_REPORT),
            status=status,
            failure_code=failure_code,
        )


def test_report_messages_include_only_compact_evidence_fields() -> None:
    evidence = _evidence()

    messages = build_report_messages(_facts(), evidence)

    payload = json.loads(messages[1]["content"])
    assert set(payload["evidence"][0]) == {
        "knowledge_id",
        "title_zh",
        "risk_domain",
        "summary",
        "recommendations",
    }
    serialized_messages = json.dumps(messages, ensure_ascii=False)
    assert evidence[0].source.url not in serialized_messages
    assert "source" not in payload["evidence"][0]
    assert "publisher" not in payload["evidence"][0]
    assert "retrieval_score" not in payload["evidence"][0]
    assert "matched_tags" not in payload["evidence"][0]


@pytest.mark.parametrize(
    ("raw", "failure_code"),
    [
        (TimeoutError("SAFE_PRIVATE_TIMEOUT"), "runtime_timeout"),
        (RuntimeError("SAFE_PRIVATE_RUNTIME_ERROR"), "runtime_error"),
        ("{not valid json", "invalid_report_json"),
        (
            json.dumps({**VALID_REPORT, "decision": "allow"}),
            "invalid_report_schema",
        ),
        (
            json.dumps({**VALID_REPORT, "evidence_ids": ["unknown-id"]}),
            "invalid_report_citation",
        ),
    ],
)
def test_qwen_generator_returns_fixed_failure_codes_without_private_details(
    raw: str | Exception,
    failure_code: str,
) -> None:
    evidence = _evidence()
    generation = QwenGroundedReportGenerator(FakeStructuredRuntime(raw)).generate(
        _facts(),
        evidence,
    )

    assert generation.status == "fallback"
    assert generation.failure_code == failure_code
    assert generation.report.evidence_ids == (evidence[0].knowledge_id,)
    serialized = generation.model_dump_json()
    assert "SAFE_PRIVATE_TIMEOUT" not in serialized
    assert "SAFE_PRIVATE_RUNTIME_ERROR" not in serialized
    assert "not valid json" not in serialized


def test_qwen_generator_timeout_with_empty_recommendations_still_falls_back() -> None:
    evidence = [item.model_copy(update={"recommendations": ()}) for item in _evidence()]

    generation = QwenGroundedReportGenerator(
        FakeStructuredRuntime(TimeoutError("SAFE_PRIVATE_TIMEOUT"))
    ).generate(_facts(), evidence)

    assert generation.status == "fallback"
    assert generation.failure_code == "runtime_timeout"
    assert generation.report.evidence_ids == (evidence[0].knowledge_id,)
    assert generation.report.handling_steps
