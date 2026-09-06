from __future__ import annotations

import pytest

from app.security_agent.models import AgentEvidence, AgentHypothesis
from app.security_agent.reporting import AgentReportError, render_case_report


def evidence(identifier: str, authenticity: str) -> AgentEvidence:
    return AgentEvidence(
        evidence_id=identifier,
        authenticity=authenticity,
        source_type="pcap_detection",
        source_ref="batch_01",
        summary=f"{authenticity} evidence summary",
        observed_at="2026-09-07T08:00:00Z",
        uncertainty="Does not prove attack success.",
    )


def test_report_groups_provenance_and_cites_every_finding() -> None:
    items = (
        evidence("ev_real", "real"),
        evidence("ev_sim", "simulated"),
        evidence("ev_derived", "derived"),
    )
    hypothesis = AgentHypothesis(
        hypothesis_id="hyp_01",
        title="Prompt injection reconnaissance",
        status="investigating",
        confidence=0.62,
        supporting_evidence_refs=("ev_real",),
        opposing_evidence_refs=("ev_derived",),
    )

    report = render_case_report(
        title="Investigation",
        objective="Find anomalous traffic.",
        evidence=items,
        hypotheses=(hypothesis,),
        limitations=("Encrypted payload is unavailable.",),
        final_status="inconclusive",
    )

    assert "## 真实证据" in report
    assert "## 仿真证据" in report
    assert "## 派生证据" in report
    assert "[ev_real]" in report
    assert "支持证据" in report
    assert "反对证据" in report
    assert "不能证明" in report
    assert "未覆盖与失败" in report
    assert "处置与验证" in report


def test_report_rejects_hypothesis_reference_outside_case() -> None:
    hypothesis = AgentHypothesis(
        hypothesis_id="hyp_01",
        title="Unknown hypothesis",
        status="investigating",
        confidence=0.4,
        supporting_evidence_refs=("ev_missing",),
    )

    with pytest.raises(AgentReportError, match="unknown evidence"):
        render_case_report(
            title="Investigation",
            objective="Investigate.",
            evidence=(evidence("ev_real", "real"),),
            hypotheses=(hypothesis,),
            limitations=("Limited scope.",),
            final_status="inconclusive",
        )

