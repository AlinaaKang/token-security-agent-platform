from __future__ import annotations

from app.knowledge.models import KnowledgeEvidence
from app.lab.models import CounterfactualResult, CounterfactualSnapshot
from app.lab.reporting import build_case_report
from app.lab.tools import build_response_plan, execute_dry_run


def _evidence(knowledge_id: str = "owasp-llm01-prompt-injection") -> KnowledgeEvidence:
    return KnowledgeEvidence.model_validate(
        {
            "knowledge_id": knowledge_id,
            "title_zh": "提示词注入控制",
            "risk_domain": "prompt_injection",
            "summary": "使用分层控制限制提示词注入风险。",
            "recommendations": ["保留基础检测动作。"],
            "source": {
                "publisher": "owasp",
                "title": "OWASP GenAI Security Project",
                "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                "version": "2025",
                "verified_at": "2026-08-26T00:00:00Z",
                "usage_note": "official summary",
            },
            "retrieval_score": 4.0,
            "matched_tags": ["jailbreak"],
        }
    )


def _counterfactual() -> CounterfactualResult:
    snapshot = CounterfactualSnapshot(
        semantic_severity="safe",
        detector_status="token_anomaly_candidate",
        risk_score=0.9,
        detector_score=9.0,
        decision="block",
        latency_ms=30.0,
    )
    return CounterfactualResult(
        interpretation="risk_reduced",
        reason="completed",
        char_start=12,
        calibration_version="cal-v2",
        original=snapshot,
        rechecked=snapshot.model_copy(
            update={"risk_score": 0.2, "detector_score": 1.0, "decision": "allow"}
        ),
        risk_score_delta=0.7,
        detector_score_delta=8.0,
        action_changed=True,
    )


def test_case_report_cites_only_returned_knowledge_ids() -> None:
    evidence = (_evidence(),)
    plans = build_response_plan(
        decision="block",
        fusion_reason="cpd_candidate",
        mode="analysis",
        evidence=evidence,
    )
    results = tuple(execute_dry_run(plan, inject_failure=False) for plan in plans)

    report = build_case_report(
        decision="block",
        evidence=evidence,
        counterfactual=_counterfactual(),
        tool_results=results,
        requested_evidence_ids=("owasp-llm01-prompt-injection",),
    )

    assert report.report_status == "deterministic"
    assert report.evidence_ids == ("owasp-llm01-prompt-injection",)
    assert set(report.tool_statuses.values()) == {"succeeded"}
    assert any("不构成严格因果证明" in item for item in report.limitations)
    assert any("模拟" in item for item in report.limitations)


def test_unknown_citation_forces_a_valid_deterministic_fallback() -> None:
    evidence = (_evidence(),)

    report = build_case_report(
        decision="review",
        evidence=evidence,
        counterfactual=_counterfactual(),
        tool_results=(),
        requested_evidence_ids=("unknown-reference",),
    )

    assert report.report_status == "fallback"
    assert report.evidence_ids == ("owasp-llm01-prompt-injection",)
    assert "unknown-reference" not in report.model_dump_json()


def test_case_report_accepts_no_evidence_without_inventing_a_citation() -> None:
    report = build_case_report(
        decision="allow",
        evidence=(),
        counterfactual=_counterfactual(),
        tool_results=(),
        requested_evidence_ids=(),
    )

    assert report.report_status == "deterministic"
    assert report.evidence_ids == ()
    assert any("知识证据不可用" in item for item in report.limitations)
