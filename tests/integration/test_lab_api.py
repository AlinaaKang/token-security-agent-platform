from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier, BrokenBarrierError
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.lab import router as lab_router
from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.models import FORBIDDEN_PUBLIC_KEYS, LabRunRequest
from app.lab.service import LabService
from app.lab.store import LabRunStore
from app.main import app
from tests.unit.test_lab_service import RecordingWorkflow


FORBIDDEN = FORBIDDEN_PUBLIC_KEYS


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
        metrics = client.get("/api/v1/lab/metrics")

    assert scenarios.status_code == 200
    assert created.status_code == 201
    assert loaded.status_code == 200
    assert dry_run.status_code == 200
    assert metrics.status_code == 200
    assert dry_run.json()["tool_results"][0]["status"] == "failed"
    assert dry_run.json()["tool_results"][0]["effective_action"] == "block"
    assert metrics.json()["run_count"] == 1
    assert metrics.json()["tool_failure_count"] == 1
    for response in (scenarios, created, loaded, dry_run, metrics):
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


def test_confirmed_execution_is_created_then_idempotently_replayed(
    tmp_path: Path,
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    service = LabService(
        workflow=RecordingWorkflow(), execution_store=store
    )
    run = service.create_run(
        LabRunRequest(scenario_kind="custom", custom_input="Safe input")
    )
    first_key = "00000000-0000-0000-0000-000000000011"
    second_key = "00000000-0000-0000-0000-000000000012"

    with installed_lab(enabled=True, service=service):
        client = TestClient(app)
        first = client.post(
            f"/api/v1/lab/runs/{run.run_id}/tools/gateway_enforcement/execute",
            json={"confirmed": True, "idempotency_key": first_key},
        )
        replay = client.post(
            f"/api/v1/lab/runs/{run.run_id}/tools/gateway_enforcement/execute",
            json={"confirmed": True, "idempotency_key": first_key},
        )
        second = client.post(
            f"/api/v1/lab/runs/{run.run_id}/tools/gateway_enforcement/execute",
            json={"confirmed": True, "idempotency_key": second_key},
        )
        listed = client.get(f"/api/v1/lab/runs/{run.run_id}/executions")

    assert first.status_code == 201
    assert replay.status_code == 200
    assert second.status_code == 201
    assert replay.json() == first.json()
    assert second.json()["execution_id"] != first.json()["execution_id"]
    assert [item["execution_id"] for item in listed.json()] == [
        second.json()["execution_id"],
        first.json()["execution_id"],
    ]
    assert "payload" not in first.json()
    store.close()


def test_execute_rejects_confirmation_false_and_client_tool_parameters(
    tmp_path: Path,
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    service = LabService(
        workflow=RecordingWorkflow(), execution_store=store
    )
    run = service.create_run(
        LabRunRequest(scenario_kind="custom", custom_input="Safe input")
    )
    route = f"/api/v1/lab/runs/{run.run_id}/tools/security_case/execute"
    key = "00000000-0000-0000-0000-000000000013"

    with installed_lab(enabled=True, service=service):
        client = TestClient(app)
        unconfirmed = client.post(
            route, json={"confirmed": False, "idempotency_key": key}
        )
        injected = [
            client.post(
                route,
                json={"confirmed": True, "idempotency_key": key, field: "x"},
            )
            for field in ("action", "url", "command", "credential")
        ]

    assert unconfirmed.status_code == 422
    assert [response.status_code for response in injected] == [422, 422, 422, 422]
    assert service.list_executions(run.run_id) == ()
    store.close()


def test_request_validation_errors_do_not_reflect_forbidden_fields_or_values() -> None:
    service = LabService(workflow=RecordingWorkflow())
    payload = {
        "confirmed": False,
        "idempotency_key": "not-a-uuid",
        "action": "PRIVATE_ACTION",
        "url": "PRIVATE_URL",
        "command": "PRIVATE_COMMAND",
        "credential": "PRIVATE_CREDENTIAL",
        "prompt": "PRIVATE_PROMPT",
        "suffix": "PRIVATE_SUFFIX",
        "token_text": "PRIVATE_TOKEN",
        "hidden_reasoning": "PRIVATE_REASONING",
    }

    with installed_lab(enabled=True, service=service):
        response = TestClient(app).post(
            "/api/v1/lab/runs/unknown/tools/security_case/execute",
            json=payload,
        )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "request_validation_failed",
            "message": "request validation failed",
        }
    }
    for forbidden in (*payload, *payload.values()):
        assert str(forbidden) not in response.text


def test_all_execution_api_surfaces_keep_the_request_sentinel_private(
    tmp_path: Path,
) -> None:
    sentinel = "TASK9_API_PRIVATE_SENTINEL_70a02f5d"
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    service = LabService(workflow=RecordingWorkflow(), execution_store=store)

    with installed_lab(enabled=True, service=service):
        client = TestClient(app)
        health = client.get("/health")
        created = client.post(
            "/api/v1/lab/runs",
            json={
                "scenario_kind": "custom",
                "custom_input": sentinel,
                "mode": "analysis",
            },
        )
        run_id = created.json()["run_id"]
        loaded = client.get(f"/api/v1/lab/runs/{run_id}")
        dry_run = client.post(
            f"/api/v1/lab/runs/{run_id}/tools/gateway_enforcement/dry-run",
            json={"inject_failure": False},
        )
        executed = client.post(
            f"/api/v1/lab/runs/{run_id}/tools/evidence_bundle/execute",
            json={
                "confirmed": True,
                "idempotency_key": "00000000-0000-0000-0000-000000000091",
            },
        )
        listed = client.get(f"/api/v1/lab/runs/{run_id}/executions")
        artifact = client.get(
            f"/api/v1/lab/artifacts/{executed.json()['artifact_id']}/download"
        )
        invalid = client.post(
            f"/api/v1/lab/runs/{run_id}/tools/security_case/execute",
            json={
                "confirmed": False,
                "idempotency_key": "not-a-uuid",
                "hidden_reasoning": sentinel,
            },
        )

    responses = (health, created, loaded, dry_run, executed, listed, artifact, invalid)
    assert [response.status_code for response in responses] == [
        200, 201, 200, 200, 201, 200, 200, 422
    ]
    assert invalid.json() == {
        "error": {
            "code": "request_validation_failed",
            "message": "request validation failed",
        }
    }
    for response in responses:
        assert sentinel not in response.text
        if response.headers.get("content-type", "").startswith("application/json"):
            assert _forbidden_hits(response.json()) == []
    store.close()


def test_execute_returns_fixed_errors_for_unknown_expired_runs_and_tools(
    tmp_path: Path,
) -> None:
    now = [0.0]
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    service = LabService(
        workflow=RecordingWorkflow(),
        run_store=LabRunStore(ttl_seconds=1.0, clock=lambda: now[0]),
        execution_store=store,
    )
    run = service.create_run(
        LabRunRequest(scenario_kind="custom", custom_input="Safe input")
    )
    payload = {
        "confirmed": True,
        "idempotency_key": "00000000-0000-0000-0000-000000000014",
    }
    now[0] = 2.0

    with installed_lab(enabled=True, service=service):
        client = TestClient(app)
        unknown = client.post(
            "/api/v1/lab/runs/unknown/tools/security_case/execute", json=payload
        )
        expired = client.post(
            f"/api/v1/lab/runs/{run.run_id}/tools/security_case/execute",
            json=payload,
        )
        invalid_tool = client.post(
            f"/api/v1/lab/runs/{run.run_id}/tools/arbitrary_command/execute",
            json=payload,
        )

    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "lab_run_not_found"
    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "lab_run_expired"
    assert invalid_tool.status_code == 404
    assert invalid_tool.json()["error"]["code"] == "lab_tool_not_found"
    store.close()


def test_persistence_failure_is_not_reported_as_a_successful_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    service = LabService(
        workflow=RecordingWorkflow(), execution_store=store
    )
    run = service.create_run(
        LabRunRequest(scenario_kind="custom", custom_input="Safe input")
    )

    def fail(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("PRIVATE_DATABASE_PATH")

    monkeypatch.setattr(store, "commit_result", fail)
    with installed_lab(enabled=True, service=service):
        response = TestClient(app).post(
            f"/api/v1/lab/runs/{run.run_id}/tools/gateway_enforcement/execute",
            json={
                "confirmed": True,
                "idempotency_key": str(UUID(int=15)),
            },
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "lab_tool_storage_unavailable"
    assert "PRIVATE" not in response.text
    store.close()


def test_same_key_concurrent_execute_across_two_connections_is_one_create_one_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "shared.sqlite3"
    first_store = SQLiteLabExecutionStore(path)
    second_store = SQLiteLabExecutionStore(path)
    run_store = LabRunStore()
    first_service = LabService(
        workflow=RecordingWorkflow(),
        run_store=run_store,
        execution_store=first_store,
    )
    second_service = LabService(
        workflow=RecordingWorkflow(),
        run_store=run_store,
        execution_store=second_store,
    )
    run = first_service.create_run(
        LabRunRequest(scenario_kind="custom", custom_input="Safe input")
    )
    transaction_reads = Barrier(2)

    def synchronize_first_transaction_read(store: SQLiteLabExecutionStore) -> None:
        original = store._get_by_idempotency_unlocked

        def synchronized(*args):
            existing = original(*args)
            if existing is None:
                try:
                    transaction_reads.wait(timeout=0.25)
                except BrokenBarrierError:
                    pass
            return existing

        monkeypatch.setattr(store, "_get_by_idempotency_unlocked", synchronized)

    synchronize_first_transaction_read(first_store)
    synchronize_first_transaction_read(second_store)

    def client_for(service: LabService) -> TestClient:
        application = FastAPI()
        application.state.lab_enabled = True
        application.state.lab_service = service
        application.include_router(lab_router)
        return TestClient(application)

    first_client = client_for(first_service)
    second_client = client_for(second_service)
    route = f"/api/v1/lab/runs/{run.run_id}/tools/gateway_enforcement/execute"
    payload = {
        "confirmed": True,
        "idempotency_key": "00000000-0000-0000-0000-000000000041",
    }

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(first_client.post, route, json=payload)
        second_future = pool.submit(second_client.post, route, json=payload)
        responses = (first_future.result(), second_future.result())

    assert sorted(response.status_code for response in responses) == [200, 201]
    assert responses[0].json()["execution_id"] == responses[1].json()["execution_id"]
    assert len(first_store.list_executions(run.run_id)) == 1
    assert len(second_store.list_executions(run.run_id)) == 1
    first_store.close()
    second_store.close()
