from __future__ import annotations

import pytest

from app.detection.cpd import RobustBaseline, run_cpd


def test_positive_cusum_matches_cpdonline_synthetic_fixture() -> None:
    trace = run_cpd(
        [10.0, 10.5, 12.0, 9.0, 13.0],
        RobustBaseline(median=10.0, mad_scale=2.0),
        k=0.5,
        h=10.0,
    )

    assert trace.z_scores == pytest.approx((0.0, 0.25, 1.0, -0.5, 1.5))
    assert trace.cumulative == pytest.approx((0.0, 0.0, 0.5, 0.0, 1.0))
    assert trace.alarm_index is None
