from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.main import app
from tests.unit.test_lab_service import RecordingWorkflow


def _configured_health() -> dict[str, object]:
    return {
        "status": "ok",
        "api": {"ready": True},
        "model": {"ready": True, "model_id": "qwen-model"},
        "detector": {"ready": True, "calibration_version": "cal-v2"},
        "semantic_guard": {
            "ready": True,
            "model_id": "guard-model",
            "model_version": "guard-v1",
        },
        "knowledge": {
            "ready": True,
            "snapshot_version": "official-v1",
            "card_count": 1,
            "generator_ready": True,
        },
    }


def _install_configured_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = RecordingWorkflow()
    monkeypatch.setattr(
        main_module.ServiceConfig,
        "from_environ",
        staticmethod(lambda _environ: object()),
    )
    monkeypatch.setattr(
        main_module,
        "load_service_bundle",
        lambda _config: SimpleNamespace(
            workflow=workflow,
            health=_configured_health(),
        ),
    )


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


def test_lifespan_reports_ready_sqlite_tool_storage_and_closes_it(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_configured_bundle(monkeypatch)
    monkeypatch.setenv("TOKEN_SECURITY_LAB_ENABLED", "true")
    monkeypatch.setenv(
        "TOKEN_SECURITY_EVENT_DB_PATH", str(tmp_path / "shared.sqlite3")
    )
    real_store = main_module.SQLiteLabExecutionStore
    created_stores = []

    def capture_store(path):
        store = real_store(path)
        created_stores.append(store)
        return store

    monkeypatch.setattr(main_module, "SQLiteLabExecutionStore", capture_store)

    with TestClient(app) as client:
        health = client.get("/health")
        lab_route = client.get("/api/v1/lab/scenarios")

    assert health.json()["lab"] == {
        "enabled": True,
        "ready": True,
        "reason": "ready",
        "tool_storage": "sqlite",
    }
    assert lab_route.status_code == 200
    assert len(created_stores) == 1
    with pytest.raises(Exception):
        created_stores[0].list_executions("run-after-close")
    assert not hasattr(app.state, "analysis_workflow")
    assert not hasattr(app.state, "event_store")
    assert not hasattr(app.state, "lab_service")


def test_tool_storage_failure_keeps_analysis_ready_and_execution_unavailable(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_configured_bundle(monkeypatch)
    monkeypatch.setenv("TOKEN_SECURITY_LAB_ENABLED", "true")
    monkeypatch.setenv(
        "TOKEN_SECURITY_EVENT_DB_PATH", str(tmp_path / "shared.sqlite3")
    )

    def fail_store(_path):
        raise RuntimeError("PRIVATE_STORAGE_PATH")

    monkeypatch.setattr(main_module, "SQLiteLabExecutionStore", fail_store)

    with TestClient(app) as client:
        health = client.get("/health")
        analyzed = client.post(
            "/api/v1/analyze",
            json={
                "prompt": "Safe input",
                "model_id": "qwen-model",
                "mode": "analysis",
            },
        )
        execution = client.post(
            "/api/v1/lab/runs/unknown/tools/security_case/execute",
            json={
                "confirmed": True,
                "idempotency_key": "00000000-0000-0000-0000-000000000031",
            },
        )

    assert health.json()["lab"] == {
        "enabled": True,
        "ready": False,
        "reason": "tool_storage_unavailable",
        "tool_storage": None,
    }
    assert analyzed.status_code == 200
    assert execution.status_code == 503
    assert execution.json()["error"]["code"] == "lab_unavailable"
    assert "PRIVATE" not in execution.text
