from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.lab.execution_models import LabExecuteRequest, LabExecutionErrorCode
from app.lab.models import LabRunRequest, LabToolId, ToolDryRunRequest
from app.lab.service import (
    LabExecutionInvariantViolation,
    LabRunCreationFailed,
    LabToolStorageUnavailable,
)
from app.lab.store import LabRunExpired, LabRunNotFound


router = APIRouter(prefix="/api/v1/lab", tags=["lab"])


def _error(*, status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def _service(request: Request) -> tuple[Any | None, JSONResponse | None]:
    if not getattr(request.app.state, "lab_enabled", False):
        return None, _error(
            status_code=503,
            code="lab_disabled",
            message="security lab is disabled",
        )
    service = getattr(request.app.state, "lab_service", None)
    if service is None:
        return None, _error(
            status_code=503,
            code="lab_unavailable",
            message="security lab dependencies are unavailable",
        )
    return service, None


@router.get("/scenarios")
def list_scenarios(request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    return service.list_scenarios()


@router.get("/metrics")
def get_metrics(request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    return service.metrics()


@router.post("/runs", status_code=201)
def create_run(payload: LabRunRequest, request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        return service.create_run(payload)
    except LabRunCreationFailed:
        return _error(
            status_code=500,
            code="lab_run_failed",
            message="security lab run failed",
        )


@router.get("/runs/{run_id}")
def get_run(run_id: str, request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        return service.get_run(run_id)
    except LabRunExpired:
        return _error(
            status_code=410,
            code="lab_run_expired",
            message="security lab run expired",
        )
    except LabRunNotFound:
        return _error(
            status_code=404,
            code="lab_run_not_found",
            message="security lab run was not found",
        )


@router.post("/runs/{run_id}/tools/{tool_id}/dry-run")
def dry_run_tool(
    run_id: str,
    tool_id: str,
    payload: ToolDryRunRequest,
    request: Request,
) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        selected_tool = LabToolId(tool_id)
    except ValueError:
        return _error(
            status_code=404,
            code="lab_tool_not_found",
            message="security lab tool was not found",
        )
    try:
        return service.run_tool(
            run_id,
            selected_tool,
            inject_failure=payload.inject_failure,
        )
    except LabRunExpired:
        return _error(
            status_code=410,
            code="lab_run_expired",
            message="security lab run expired",
        )
    except LabRunNotFound:
        return _error(
            status_code=404,
            code="lab_run_not_found",
            message="security lab run was not found",
        )


@router.post("/runs/{run_id}/tools/{tool_id}/execute", status_code=201)
def execute_tool(
    run_id: str,
    tool_id: str,
    payload: LabExecuteRequest,
    request: Request,
) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        selected_tool = LabToolId(tool_id)
    except ValueError:
        return _error(
            status_code=404,
            code="lab_tool_not_found",
            message="security lab tool was not found",
        )
    try:
        execution, newly_created = service.execute_tool(
            run_id, selected_tool, payload
        )
    except LabRunExpired:
        return _error(
            status_code=410,
            code="lab_run_expired",
            message="security lab run expired",
        )
    except LabRunNotFound:
        return _error(
            status_code=404,
            code="lab_run_not_found",
            message="security lab run was not found",
        )
    except LabToolStorageUnavailable:
        return _tool_storage_unavailable()
    except LabExecutionInvariantViolation:
        return _error(
            status_code=500,
            code="lab_execution_failed",
            message="security lab tool execution failed",
        )
    if execution.error_code is LabExecutionErrorCode.PERSISTENCE_FAILED:
        return _tool_storage_unavailable()
    return JSONResponse(
        status_code=201 if newly_created else 200,
        content=execution.model_dump(mode="json"),
    )


@router.get("/runs/{run_id}/executions")
def list_executions(run_id: str, request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        return service.list_executions(run_id)
    except LabToolStorageUnavailable:
        return _tool_storage_unavailable()


@router.get("/artifacts/{artifact_id}/download")
def download_artifact(artifact_id: str, request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        artifact = service.get_artifact(artifact_id)
    except LookupError:
        return _error(
            status_code=404,
            code="lab_artifact_not_found",
            message="security lab artifact was not found",
        )
    except LabToolStorageUnavailable:
        return _tool_storage_unavailable()
    actual_sha256 = "sha256:" + hashlib.sha256(artifact.payload).hexdigest()
    if actual_sha256 != artifact.sha256:
        return _error(
            status_code=409,
            code="lab_artifact_integrity_failed",
            message="security lab artifact integrity check failed",
        )
    return Response(
        content=artifact.payload,
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": 'attachment; filename="lab-evidence.json"',
            "ETag": artifact.sha256,
            "X-Content-Type-Options": "nosniff",
        },
    )


def _tool_storage_unavailable() -> JSONResponse:
    return _error(
        status_code=503,
        code="lab_tool_storage_unavailable",
        message="security lab tool storage is unavailable",
    )
