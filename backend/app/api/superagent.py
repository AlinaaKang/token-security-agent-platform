from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.pcap.authorization import (
    PcapAuthorizationAlreadyUsed,
    PcapAuthorizationExpired,
    PcapAuthorizationUnknown,
)
from app.superagent.models import (
    PcapTriageMissionRequest,
    SuperAgentCreateMissionRequest,
)
from app.superagent.service import (
    SuperAgentMissionFailed,
    SuperAgentService,
)
from app.superagent.store import (
    SuperAgentMissionExpired,
    SuperAgentMissionNotFound,
)


router = APIRouter(prefix="/api/v1/superagent", tags=["superagent"])


class _PcapAuthorizationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed: Literal[True]
    max_files: int = Field(ge=1, le=20, strict=True)


def _default_prompt_objective(value: Any) -> Any:
    if isinstance(value, dict) and "objective" not in value:
        return {"objective": "investigate_and_respond", **value}
    return value


_ApiCreateMissionRequest = Annotated[
    SuperAgentCreateMissionRequest,
    BeforeValidator(_default_prompt_objective),
]


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


def _pcap_unavailable() -> JSONResponse:
    return _error(
        status_code=503,
        code="pcap_triage_unavailable",
        message="pcap triage is unavailable",
    )


def _pcap_batch_failed() -> JSONResponse:
    return _error(
        status_code=500,
        code="pcap_batch_failed",
        message="pcap batch triage failed",
    )


def _pcap_components(request: Request) -> tuple[Any, Any, Any] | None:
    authorization_store = getattr(
        request.app.state, "pcap_authorization_store", None
    )
    executor = getattr(request.app.state, "pcap_executor", None)
    coordinator = getattr(request.app.state, "pcap_coordinator", None)
    if authorization_store is None or executor is None or coordinator is None:
        return None
    return authorization_store, executor, coordinator


@router.get("/capabilities")
def capabilities(request: Request) -> Any:
    service, error = _service(request)
    if error is not None:
        return error
    return service.capabilities()


@router.get("/pcap/capabilities")
def pcap_capabilities(request: Request) -> Any:
    components = _pcap_components(request)
    if components is None:
        return _pcap_unavailable()
    try:
        return components[1].overview()
    except Exception:
        return _pcap_batch_failed()


@router.get("/pcap/overview")
def pcap_overview(request: Request) -> Any:
    components = _pcap_components(request)
    if components is None:
        return _pcap_unavailable()
    try:
        return components[1].overview()
    except Exception:
        return _pcap_batch_failed()


@router.post("/pcap/authorizations", status_code=201)
def authorize_pcap(
    payload: _PcapAuthorizationPayload, request: Request
) -> Any:
    components = _pcap_components(request)
    if components is None:
        return _pcap_unavailable()
    try:
        return components[0].issue(payload.max_files)
    except Exception:
        return _pcap_batch_failed()


@router.post("/missions", status_code=201)
def create_mission(payload: _ApiCreateMissionRequest, request: Request) -> Any:
    if isinstance(payload, PcapTriageMissionRequest):
        components = _pcap_components(request)
        if components is None:
            return _pcap_unavailable()
        try:
            return components[2].start(payload)
        except PcapAuthorizationUnknown:
            return _error(
                status_code=403,
                code="pcap_authorization_required",
                message="pcap authorization is required",
            )
        except PcapAuthorizationExpired:
            return _error(
                status_code=410,
                code="pcap_authorization_expired",
                message="pcap authorization expired",
            )
        except PcapAuthorizationAlreadyUsed:
            return _error(
                status_code=409,
                code="pcap_authorization_used",
                message="pcap authorization was already used",
            )
        except Exception:
            return _pcap_batch_failed()
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
    service = getattr(request.app.state, "superagent_service", None)
    if service is not None:
        mission_store = service.mission_store
    else:
        components = _pcap_components(request)
        if components is None:
            return _service(request)[1]
        mission_store = components[2].mission_store
    try:
        return mission_store.get(mission_id)
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


@router.post("/missions/{mission_id}/cancel")
def cancel_pcap_mission(mission_id: str, request: Request) -> Any:
    components = _pcap_components(request)
    if components is None:
        return _pcap_unavailable()
    try:
        return components[2].cancel(mission_id)
    except (SuperAgentMissionExpired, SuperAgentMissionNotFound):
        return _error(
            status_code=409,
            code="pcap_mission_not_cancellable",
            message="pcap mission is not cancellable",
        )
    except Exception:
        return _pcap_batch_failed()
