from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from fastapi.testclient import TestClient

from app.lab.service import LabService
from app.main import app
from tests.unit.test_lab_service import RecordingWorkflow


FORBIDDEN = {
    "prompt",
    "suffix",
    "token_text",
    "token_id",
    "query_text",
    "raw_output",
    "guard_raw_output",
}


def _forbidden_hits(value: object) -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN:
                hits.append(key)
            hits.extend(_forbidden_hits(child))
    elif isinstance(value, list):
        for child in value:
            hits.extend(_forbidden_hits(child))
    return hits


@contextmanager
def installed_lab(*, enabled: bool, service: LabService | None) -> Iterator[None]:
    previous_enabled = getattr(app.state, "lab_enabled", None)
    previous_service = getattr(app.state, "lab_service", None)
    app.state.lab_enabled = enabled
    if service is None:
        if hasattr(app.state, "lab_service"):
            del app.state.lab_service
    else:
        app.state.lab_service = service
    try:
        yield
    finally:
        if previous_enabled is None:
            del app.state.lab_enabled
        else:
            app.state.lab_enabled = previous_enabled
        if previous_service is None:
            if hasattr(app.state, "lab_service"):
                del app.state.lab_service
        else:
            app.state.lab_service = previous_service


def test_lab_routes_return_a_stable_disabled_error() -> None:
    with installed_lab(enabled=False, service=None):
        response = TestClient(app).get("/api/v1/lab/scenarios")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "lab_disabled"


def test_enabled_lab_reports_unavailable_without_a_service() -> None:
    with installed_lab(enabled=True, service=None):
        response = TestClient(app).get("/api/v1/lab/scenarios")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "lab_unavailable"


def test_lab_api_creates_reads_and_dry_runs_a_redacted_custom_run() -> None:
    service = LabService(workflow=RecordingWorkflow())
    with installed_lab(enabled=True, service=service):
        client = TestClient(app)
        scenarios = client.get("/api/v1/lab/scenarios")
        created = client.post(
            "/api/v1/lab/runs",
            json={
                "scenario_kind": "custom",
                "custom_input": "Safe prefix. PRIVATE_CONTINUATION",
                "mode": "gateway",
            },
        )
        run_id = created.json()["run_id"]
        loaded = client.get(f"/api/v1/lab/runs/{run_id}")
        dry_run = client.post(
            f"/api/v1/lab/runs/{run_id}/tools/gateway_preview/dry-run",
            json={"inject_failure": True},
        )

    assert scenarios.status_code == 200
    assert created.status_code == 201
    assert loaded.status_code == 200
    assert dry_run.status_code == 200
    assert dry_run.json()["tool_results"][0]["status"] == "failed"
    assert dry_run.json()["tool_results"][0]["effective_action"] == "block"
    for response in (scenarios, created, loaded, dry_run):
        assert _forbidden_hits(response.json()) == []
        assert "PRIVATE_CONTINUATION" not in response.text


def test_lab_api_rejects_unknown_runs_and_tool_ids_with_fixed_codes() -> None:
    service = LabService(workflow=RecordingWorkflow())
    with installed_lab(enabled=True, service=service):
        client = TestClient(app)
        missing = client.get("/api/v1/lab/runs/unknown")
        invalid_tool = client.post(
            "/api/v1/lab/runs/unknown/tools/arbitrary_command/dry-run",
            json={"inject_failure": False},
        )

    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "lab_run_not_found"
    assert invalid_tool.status_code == 404
    assert invalid_tool.json()["error"]["code"] == "lab_tool_not_found"


def test_lab_api_rejects_extra_execution_parameters() -> None:
    service = LabService(workflow=RecordingWorkflow())
    with installed_lab(enabled=True, service=service):
        response = TestClient(app).post(
            "/api/v1/lab/runs/unknown/tools/gateway_preview/dry-run",
            json={
                "inject_failure": False,
                "url": "https://example.invalid",
                "command": "run",
            },
        )

    assert response.status_code == 422


def test_lab_creation_failure_returns_a_fixed_error_without_private_details() -> None:
    service = LabService(workflow=RecordingWorkflow(fail=True))
    with installed_lab(enabled=True, service=service):
        response = TestClient(app).post(
            "/api/v1/lab/runs",
            json={
                "scenario_kind": "custom",
                "custom_input": "PRIVATE_CUSTOM_INPUT",
                "mode": "analysis",
            },
        )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "lab_run_failed"
    assert "PRIVATE" not in response.text
