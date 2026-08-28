from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.models import LabRunRequest
from app.lab.service import LabService
from app.lab.store import LabRunStore
from app.main import app
from tests.integration.test_lab_api import installed_lab
from tests.unit.test_lab_service import RecordingWorkflow


def test_execution_list_and_artifact_download_survive_run_expiration(
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
        LabRunRequest(scenario_kind="custom", custom_input="PRIVATE_INPUT")
    )

    with installed_lab(enabled=True, service=service):
        client = TestClient(app)
        executed = client.post(
            f"/api/v1/lab/runs/{run.run_id}/tools/evidence_bundle/execute",
            json={
                "confirmed": True,
                "idempotency_key": "00000000-0000-0000-0000-000000000021",
            },
        )
        now[0] = 2.0
        listed = client.get(f"/api/v1/lab/runs/{run.run_id}/executions")
        downloaded = client.get(
            f"/api/v1/lab/artifacts/{executed.json()['artifact_id']}/download"
        )

    expected_sha256 = "sha256:" + hashlib.sha256(downloaded.content).hexdigest()
    assert executed.status_code == 201
    assert "payload" not in executed.json()
    assert listed.status_code == 200
    assert listed.json() == [executed.json()]
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"] == "application/json"
    assert downloaded.headers["content-disposition"] == (
        'attachment; filename="lab-evidence.json"'
    )
    assert downloaded.headers["etag"] == executed.json()["evidence_sha256"]
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert expected_sha256 == executed.json()["evidence_sha256"]
    assert "PRIVATE_INPUT" not in downloaded.text
    store.close()


def test_unknown_artifact_returns_a_fixed_not_found_error(tmp_path: Path) -> None:
    store = SQLiteLabExecutionStore(tmp_path / "lab.sqlite3")
    service = LabService(
        workflow=RecordingWorkflow(), execution_store=store
    )

    with installed_lab(enabled=True, service=service):
        response = TestClient(app).get(
            "/api/v1/lab/artifacts/artifact_unknown/download"
        )

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "lab_artifact_not_found",
            "message": "security lab artifact was not found",
        }
    }
    store.close()
