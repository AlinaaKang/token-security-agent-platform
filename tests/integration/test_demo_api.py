from __future__ import annotations

from fastapi.testclient import TestClient

from app.demo.service import DemoSampleService
from app.main import app
from tests.unit.test_demo_service import StubWorkflow, make_records


def test_demo_api_lists_ids_and_returns_redacted_analysis() -> None:
    service = DemoSampleService(
        records=make_records(),
        source_commit="safe-source-commit",
    )
    sample = service.list_samples(family="autodan", limit=1)[0]
    app.state.demo_service = service
    app.state.analysis_workflow = StubWorkflow()
    try:
        catalog = TestClient(app).get("/api/v1/demo-samples?family=autodan&limit=5")
        analysis = TestClient(app).post(
            f"/api/v1/demo-samples/{sample.sample_id}/analyze"
        )
        missing = TestClient(app).post(
            "/api/v1/demo-samples/unknown-id/analyze"
        )
    finally:
        del app.state.demo_service
        del app.state.analysis_workflow

    assert catalog.status_code == 200
    assert all(item["family"] == "autodan" for item in catalog.json())
    assert analysis.status_code == 200
    assert analysis.json()["result"]["signals"][0]["token_text"] == ""
    assert analysis.json()["result"]["signals"][0]["token_id"] == 0
    assert analysis.json()["result"]["semantic_severity"] == "unsafe"
    assert analysis.json()["result"]["semantic_categories"] == ["jailbreak"]
    assert analysis.json()["result"]["fusion_reason"] == "semantic_unsafe"
    serialized = analysis.text
    assert "SAFE_BASE" not in serialized
    assert "SAFE_PATTERN" not in serialized
    assert "SAFE_TOKEN_TEXT" not in serialized
    assert "Safety: Unsafe" not in serialized
    assert "guard_raw_output" not in serialized
    assert missing.status_code == 404


def test_demo_api_reports_unavailable_without_configured_sources() -> None:
    response = TestClient(app).get("/api/v1/demo-samples")

    assert response.status_code == 503
    assert response.json()["detail"] == "demo samples are unavailable"
