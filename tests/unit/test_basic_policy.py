from __future__ import annotations

from app.agent.policy import Action, BasicPolicy


def test_basic_policy_maps_low_medium_and_high_risk_to_explicit_actions() -> None:
    policy = BasicPolicy(review_threshold=0.5, block_threshold=0.8)

    assert policy.decide(0.2) is Action.ALLOW
    assert policy.decide(0.5) is Action.REVIEW
    assert policy.decide(0.8) is Action.BLOCK
