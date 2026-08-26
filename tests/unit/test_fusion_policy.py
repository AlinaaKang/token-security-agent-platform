from __future__ import annotations

import pytest

from app.agent.fusion import EvidenceFusionPolicy, FusionReason
from app.agent.policy import Action
from app.semantic.models import SemanticSeverity


@pytest.mark.parametrize(
    ("mode", "semantic", "alarm", "action", "reason"),
    [
        ("analysis", "unsafe", False, "block", "semantic_unsafe"),
        ("gateway", "unsafe", False, "block", "semantic_unsafe"),
        (
            "analysis",
            "controversial",
            False,
            "review",
            "semantic_controversial",
        ),
        (
            "gateway",
            "controversial",
            True,
            "review",
            "semantic_controversial",
        ),
        ("analysis", "safe", True, "block", "cpd_candidate"),
        ("gateway", "safe", True, "review", "cpd_candidate"),
        ("analysis", "safe", False, "allow", "all_clear"),
        ("gateway", "safe", False, "allow", "all_clear"),
        (
            "analysis",
            "unavailable",
            True,
            "block",
            "semantic_unavailable_cpd_candidate",
        ),
        (
            "gateway",
            "unavailable",
            True,
            "review",
            "semantic_unavailable_cpd_candidate",
        ),
        (
            "analysis",
            "unavailable",
            False,
            "allow",
            "semantic_unavailable_analysis_degraded",
        ),
        (
            "gateway",
            "unavailable",
            False,
            "review",
            "semantic_unavailable_gateway_fail_safe",
        ),
    ],
)
def test_fusion_table(
    mode: str,
    semantic: str,
    alarm: bool,
    action: str,
    reason: str,
) -> None:
    result = EvidenceFusionPolicy().decide(
        mode=mode,
        semantic=SemanticSeverity(semantic),
        cpd_alarm=alarm,
    )

    assert result == (Action(action), FusionReason(reason))
