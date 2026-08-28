from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

import app.evaluation.knowledge as knowledge_evaluation
from app.evaluation.knowledge import (
    KnowledgeEvaluationCase,
    KnowledgeEvaluationReport,
    evaluate_knowledge,
)
from app.knowledge.loader import load_knowledge_snapshot
from app.knowledge.models import RiskDomain


def _case(**overrides: object) -> KnowledgeEvaluationCase:
    values: dict[str, object] = {
        "case_id": "safe-case-01",
        "risk_domain": "prompt_injection",
        "safe_terms": ["prompt injection", "提示词注入"],
        "metadata": {
            "semantic_severity": "unsafe",
            "semantic_categories": ["jailbreak"],
            "detector_status": "token_anomaly_candidate",
            "fusion_reason": "semantic_unsafe",
            "decision": "block",
            "mode": "analysis",
            "attack_family": "AutoDAN",
        },
        "expected_any_ids": [
            "owasp-llm01-prompt-injection",
            "mitre-atlas-prompt-injection",
        ],
    }
    values.update(overrides)
    return KnowledgeEvaluationCase.model_validate(values)


def test_evaluation_reports_aggregate_hit_and_valid_citations_only() -> None:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v1"))

    report = evaluate_knowledge(snapshot, [_case()], split="development")

    assert report.split == "development"
    assert report.case_count == 1
    assert report.hit_at_1 == 1.0
    assert report.hit_at_3 == 1.0
    assert report.mrr == 1.0
    assert report.citation_validity == 1.0
    assert report.decision_invariance == 1.0
    assert report.decision_invariance_basis == "retrieval_has_no_decision_output"
    assert report.target_status == {
        "hit_at_3": report.hit_at_3 >= 0.95,
        "citation_validity": report.citation_validity == 1.0,
        "decision_invariance": report.decision_invariance == 1.0,
    }
    serialized = report.model_dump_json()
    assert "safe_terms" not in serialized
    assert "query_text" not in serialized
    assert "case_id" not in serialized


def test_evaluation_rejects_duplicate_cases_and_unknown_expected_ids() -> None:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v1"))
    case = _case()

    with pytest.raises(ValueError, match="unique"):
        evaluate_knowledge(snapshot, [case, case], split="development")
    with pytest.raises(ValueError, match="expected knowledge"):
        evaluate_knowledge(
            snapshot,
            [_case(expected_any_ids=["unknown-knowledge-id"])],
            split="development",
        )


def test_evaluation_rejects_unknown_split() -> None:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v1"))

    with pytest.raises(ValueError, match="split"):
        evaluate_knowledge(snapshot, [_case()], split="holdout")  # type: ignore[arg-type]


def test_evaluation_detects_nested_decision_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v1"))
    class EvidenceWithDecision(BaseModel):
        knowledge_id: str
        details: list[dict[str, str]]

    evidence = EvidenceWithDecision(
        knowledge_id="owasp-llm01-prompt-injection",
        details=[{"decision": "block"}],
    )
    monkeypatch.setattr(
        knowledge_evaluation.LocalKnowledgeRetriever,
        "search",
        lambda self, query, top_k: [evidence],
    )

    report = evaluate_knowledge(snapshot, [_case()], split="test")

    assert report.decision_invariance == 0.0
    assert report.target_status["decision_invariance"] is False


def test_legacy_v1_report_does_not_claim_verified_decision_invariance() -> None:
    raw = json.loads(
        Path("data/knowledge-evaluation-report-v1.json").read_text(encoding="ascii")
    )

    report = KnowledgeEvaluationReport.model_validate(raw)

    assert report.decision_invariance_basis == "legacy_unverified"
    assert report.decision_invariance_basis != "retrieval_has_no_decision_output"
    assert report.target_status["decision_invariance"] is False


@pytest.mark.parametrize(
    "field_value",
    [
        {"safe_terms": []},
        {"expected_any_ids": []},
        {"prompt": "SAFE_PRIVATE_QUERY"},
    ],
)
def test_evaluation_case_rejects_empty_or_forbidden_payload(
    field_value: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _case(**field_value)


def test_v2_fixtures_are_balanced_disjoint_and_redacted() -> None:
    fixture_paths = {
        "development": Path("data/knowledge-evaluation-v2-development.json"),
        "test": Path("data/knowledge-evaluation-v2-test.json"),
    }
    case_ids_by_split: dict[str, set[str]] = {}

    for split, path in fixture_paths.items():
        assert path.is_file(), f"missing {split} fixture"
        raw_cases = json.loads(path.read_text(encoding="utf-8"))
        cases = TypeAdapter(list[KnowledgeEvaluationCase]).validate_python(raw_cases)

        assert len(cases) == 36
        assert Counter(case.risk_domain for case in cases) == Counter(
            {domain: 4 for domain in RiskDomain}
        )
        prefix = "dev-v2-" if split == "development" else "test-v2-"
        case_ids_by_split[split] = {case.case_id for case in cases}
        assert all(case_id.startswith(prefix) for case_id in case_ids_by_split[split])
        assert all(
            set(raw_case)
            == {
                "case_id",
                "risk_domain",
                "safe_terms",
                "metadata",
                "expected_any_ids",
            }
            for raw_case in raw_cases
        )

    assert case_ids_by_split["development"].isdisjoint(case_ids_by_split["test"])
