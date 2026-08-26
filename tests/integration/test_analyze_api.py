from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_analyze_returns_structured_model_unavailable_error() -> None:
    response = TestClient(app).post(
        "/api/v1/analyze",
        json={
            "prompt": "Summarize this project update.",
            "model_id": "Qwen/Qwen2.5-7B-Instruct",
            "mode": "analysis",
        },
    )

    assert response.status_code == 503
    payload = response.json()
    assert payload["error"]["code"] == "model_unavailable"
    assert payload["request_id"].startswith("req_")
