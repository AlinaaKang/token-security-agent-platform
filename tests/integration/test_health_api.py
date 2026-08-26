from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_api_model_and_detector_readiness_separately() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "degraded",
        "api": {"ready": True},
        "model": {"ready": False, "model_id": None},
        "detector": {"ready": False, "calibration_version": None},
        "semantic_guard": {
            "ready": False,
            "model_id": "unconfigured",
            "model_version": "unconfigured",
        },
        "knowledge": {
            "ready": False,
            "snapshot_version": None,
            "card_count": 0,
            "generator_ready": False,
        },
        "audit": {"ready": False, "storage": None},
        "evaluation": {
            "ready": False,
            "schema_version": None,
            "deployment_match": False,
        },
        "demo": {"ready": False, "sample_count": 0},
        "lab": {"enabled": False, "ready": False, "reason": "disabled"},
    }


def test_health_reports_configured_model_and_calibration() -> None:
    app.state.service_health = {
        "status": "ok",
        "api": {"ready": True},
        "model": {"ready": True, "model_id": "qwen-model"},
        "detector": {"ready": True, "calibration_version": "demo-v1"},
        "semantic_guard": {
            "ready": True,
            "model_id": "qwen-guard",
            "model_version": "revision-id",
        },
        "knowledge": {
            "ready": True,
            "snapshot_version": "official-v1",
            "card_count": 12,
            "generator_ready": True,
        },
        "audit": {"ready": True, "storage": "sqlite"},
        "evaluation": {
            "ready": True,
            "schema_version": 2,
            "deployment_match": True,
        },
        "demo": {"ready": True, "sample_count": 100},
        "lab": {"enabled": True, "ready": False, "reason": "unavailable"},
    }
    try:
        response = TestClient(app).get("/health")
    finally:
        del app.state.service_health

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["model"]["model_id"] == "qwen-model"
    assert response.json()["detector"]["calibration_version"] == "demo-v1"
    assert response.json()["semantic_guard"]["model_version"] == "revision-id"
    assert response.json()["audit"]["ready"] is True
    assert response.json()["lab"] == {
        "enabled": True,
        "ready": False,
        "reason": "unavailable",
    }
