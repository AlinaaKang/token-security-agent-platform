from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.superagent.models import SuperAgentMissionRequest
from app.superagent.service import (
    SuperAgentMissionFailed,
    SuperAgentService,
)
from app.superagent.store import (
    SuperAgentMissionExpired,
    SuperAgentMissionNotFound,
)


router = APIRouter(prefix="/api/v1/superagent", tags=["superagent"])


def _error(*, status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def _service(request: Request) -> tuple[SuperAgentService | None, JSONResponse | None]:
    service = getattr(request.app.state, "superagent_service", None)
    if service is None:
        return None, _error(
            status_code=503,
            code="superagent_unavailable",
            message="bounded superagent dependencies are unavailable",
        )
    return service, None


@router.get("/capabilities")
def capabilities(request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    return service.capabilities()


@router.post("/missions", status_code=201)
def create_mission(payload: SuperAgentMissionRequest, request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        return service.create_mission(payload)
    except SuperAgentMissionFailed:
        return _error(
            status_code=500,
            code="superagent_mission_failed",
            message="bounded superagent mission failed",
        )


@router.get("/missions/{mission_id}")
def get_mission(mission_id: str, request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    try:
        return service.get_mission(mission_id)
    except SuperAgentMissionExpired:
        return _error(
            status_code=410,
            code="superagent_mission_expired",
            message="bounded superagent mission expired",
        )
    except SuperAgentMissionNotFound:
        return _error(
            status_code=404,
            code="superagent_mission_not_found",
            message="bounded superagent mission was not found",
        )

