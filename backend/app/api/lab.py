from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.lab.models import LabRunRequest, LabToolId, ToolDryRunRequest
from app.lab.service import LabRunCreationFailed
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
