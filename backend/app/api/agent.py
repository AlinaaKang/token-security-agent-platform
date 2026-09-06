from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from app.security_agent.coordinator import (
    AgentAuthorizationScopeMismatch,
    SecurityAgentCoordinator,
)
from app.security_agent.models import AgentCommandRequest
from app.security_agent.feedback import AnalystFeedbackService
from app.security_agent.playbooks import PlaybookInvalid, load_playbook_catalog
from app.security_agent.store import AgentTaskConflict, AgentTaskNotFound


router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


class AgentAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed: Literal[True]
    scopes: tuple[str, ...] = Field(min_length=1, max_length=8)


class AgentMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=32_768)


class AgentFeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["confirmed", "false_positive", "missed_detection", "inconclusive"]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=50)


def _service(request: Request) -> SecurityAgentCoordinator | None:
    return getattr(request.app.state, "security_agent_coordinator", None)


def _feedback_service(request: Request) -> AnalystFeedbackService | None:
    return getattr(request.app.state, "security_agent_feedback", None)


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


@router.get("/playbooks")
def playbooks(request: Request) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    path = Path(__file__).resolve().parents[3] / "data" / "demo" / "security-agent-playbooks.json"
    try:
        return load_playbook_catalog(path, service.registry)
    except PlaybookInvalid:
        return _error(503, "agent_playbooks_unavailable", "security playbooks are unavailable")


@router.get("/connectors")
def connectors(request: Request) -> Any:
    service = _service(request)
    if service is None:
        return _error(503, "security_agent_unavailable", "security agent is unavailable")
    titles = {
        "prompt_runtime": "Prompt 语义与 Token 运行时",
        "pcap_docker": "PCAP 隔离 Docker",
        "endpoint_demo": "端点遥测演示",
        "identity_demo": "身份行为演示",
        "gateway_log_demo": "网关日志演示",
    }
    return [
        {
            "connector_id": connector_id,
            "title": titles.get(connector_id, connector_id),
            "state": state,
            "authenticity": (
                "real" if state == "available" else "simulated" if state == "simulated" else "derived"
            ),
        }
        for connector_id, state in service.capabilities.connector_states.items()
    ]


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


@router.post("/tasks/{task_id}/feedback", status_code=201)
def record_feedback(
    task_id: str, payload: AgentFeedbackRequest, request: Request
) -> Any:
    service = _service(request)
    feedback_service = _feedback_service(request)
    if service is None or feedback_service is None:
        return _error(503, "security_agent_feedback_unavailable", "security agent feedback is unavailable")
    try:
        task = service.get(task_id)
    except AgentTaskNotFound:
        return _error(404, "agent_task_not_found", "security agent task was not found")
    known_evidence = {item.evidence_id for item in task.evidence}
    if not set(payload.evidence_refs).issubset(known_evidence):
        return _error(422, "agent_feedback_evidence_invalid", "feedback evidence reference is invalid")
    return feedback_service.record_feedback(
        task_id=task_id,
        verdict=payload.verdict,
        reason_code=payload.reason_code,
        evidence_refs=payload.evidence_refs,
    )


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
