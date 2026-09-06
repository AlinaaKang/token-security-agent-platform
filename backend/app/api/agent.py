from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from app.security_agent.coordinator import (
    AgentAuthorizationScopeMismatch,
    SecurityAgentCoordinator,
)
from app.security_agent.models import AgentCommandRequest
from app.security_agent.store import AgentTaskConflict, AgentTaskNotFound


router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


class AgentAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed: Literal[True]
    scopes: tuple[str, ...] = Field(min_length=1, max_length=8)


class AgentMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=32_768)


def _service(request: Request) -> SecurityAgentCoordinator | None:
    return getattr(request.app.state, "security_agent_coordinator", None)


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


@router.get("/capabilities")
def capabilities(request: Request) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    return service.capabilities


@router.post("/tasks", status_code=201)
def create_task(payload: AgentCommandRequest, request: Request) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    try:
        return service.create(payload.message)
    except ValueError:
        return _error(422, "agent_command_invalid", "security agent command is invalid")


@router.get("/tasks")
def list_tasks(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    items = service.list(limit=limit, offset=offset)
    return {"items": items, "limit": limit, "offset": offset}


@router.get("/tasks/{task_id}")
def get_task(task_id: str, request: Request) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    try:
        return service.get(task_id)
    except AgentTaskNotFound:
        return _error(404, "agent_task_not_found", "security agent task was not found")


@router.post("/tasks/{task_id}/messages")
def add_message(task_id: str, payload: AgentMessageRequest, request: Request) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    try:
        return service.add_message(task_id, payload.message)
    except AgentTaskNotFound:
        return _error(404, "agent_task_not_found", "security agent task was not found")
    except AgentTaskConflict:
        return _error(409, "agent_task_conflict", "security agent task changed; retry")


@router.post("/tasks/{task_id}/authorizations")
def authorize_task(
    task_id: str, payload: AgentAuthorizationRequest, request: Request
) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    try:
        authorized = service.authorize(task_id, payload.scopes)
        service.start_background(task_id)
        return authorized
    except AgentTaskNotFound:
        return _error(404, "agent_task_not_found", "security agent task was not found")
    except AgentAuthorizationScopeMismatch:
        return _error(
            403,
            "agent_authorization_scope_mismatch",
            "authorization scope does not match the task",
        )
    except AgentTaskConflict:
        return _error(409, "agent_task_conflict", "security agent task changed; retry")


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str, request: Request) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    try:
        return service.cancel(task_id)
    except AgentTaskNotFound:
        return _error(404, "agent_task_not_found", "security agent task was not found")
    except AgentTaskConflict:
        return _error(409, "agent_task_conflict", "security agent task changed; retry")


@router.get("/tasks/{task_id}/events")
def task_events(task_id: str, request: Request) -> Response:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    raw_sequence = request.headers.get("last-event-id", "0")
    try:
        sequence = int(raw_sequence)
        if sequence < 0:
            raise ValueError
        events = service.events_after(task_id, sequence)
    except ValueError:
        return _error(400, "agent_event_cursor_invalid", "event cursor is invalid")
    except AgentTaskNotFound:
        return _error(404, "agent_task_not_found", "security agent task was not found")
    body = "".join(
        f"id: {event.sequence}\nevent: {event.kind}\ndata: {json.dumps(event.model_dump(mode='json'), ensure_ascii=False)}\n\n"
        for event in events
    )
    return Response(
        content=body,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/reports/{report_id}")
def get_report(report_id: str, request: Request) -> Response:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    report = service.report(report_id)
    if report is None:
        return _error(404, "agent_report_not_found", "security agent report was not found")
    return Response(content=report, media_type="text/markdown; charset=utf-8")

