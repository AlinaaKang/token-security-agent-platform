from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.evaluation.service import EvaluationReportService
from app.main import app
from tests.unit.test_evaluation_service import safe_report


def test_evaluation_api_returns_validated_summary() -> None:
    path = Path("tmp/test-evaluation-api.json")
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(safe_report()), encoding="utf-8")
    app.state.evaluation_service = EvaluationReportService(path)
    app.state.active_calibration_version = "cal-v1"
    try:
        response = TestClient(app).get("/api/v1/evaluation/summary")
    finally:
        del app.state.evaluation_service
        del app.state.active_calibration_version
        path.unlink(missing_ok=True)

    assert response.status_code == 200
    assert response.json()["deployment_match"] is True
    assert set(response.json()["methods"]) == {
        "global_nll",
        "window_nll",
        "entropy_cpd",
    }


def test_evaluation_api_returns_independent_knowledge_metrics() -> None:
    path = Path("tmp/test-evaluation-api-knowledge.json")
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(safe_report()), encoding="utf-8")
    app.state.evaluation_service = EvaluationReportService(
        path,
        knowledge_path=Path("data/knowledge-evaluation-report-v1.json"),
    )
    try:
        response = TestClient(app).get("/api/v1/evaluation/summary")
    finally:
        del app.state.evaluation_service
        path.unlink(missing_ok=True)

    assert response.status_code == 200
    knowledge = response.json()["knowledge"]
    assert knowledge["case_count"] == 36
    assert knowledge["hit_at_3"] >= 0.90
    assert knowledge["citation_validity"] == 1.0
    assert knowledge["decision_invariance"] == 1.0


def test_evaluation_api_reports_unavailable_without_configured_report() -> None:
    response = TestClient(app).get("/api/v1/evaluation/summary")

    assert response.status_code == 503
    assert response.json()["detail"] == "evaluation report is unavailable"
