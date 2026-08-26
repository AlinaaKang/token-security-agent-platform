from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.evaluation.knowledge import (
    KnowledgeEvaluationCase,
    evaluate_knowledge,
)
from app.knowledge.loader import load_knowledge_snapshot


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

    report = evaluate_knowledge(snapshot, [_case()])

    assert report.case_count == 1
    assert report.hit_at_1 == 1.0
    assert report.hit_at_3 == 1.0
    assert report.mrr == 1.0
    assert report.citation_validity == 1.0
    assert report.decision_invariance == 1.0
    serialized = report.model_dump_json()
    assert "safe_terms" not in serialized
    assert "query_text" not in serialized
    assert "case_id" not in serialized


def test_evaluation_rejects_duplicate_cases_and_unknown_expected_ids() -> None:
    snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v1"))
    case = _case()

    with pytest.raises(ValueError, match="unique"):
        evaluate_knowledge(snapshot, [case, case])
    with pytest.raises(ValueError, match="expected knowledge"):
        evaluate_knowledge(
            snapshot,
            [_case(expected_any_ids=["unknown-knowledge-id"])],
        )


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
