from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.pcap.authorization import (
    PcapAuthorizationAlreadyUsed,
    PcapAuthorizationExpired,
    PcapAuthorizationUnknown,
    PcapAuthorizationPurposeMismatch,
)
from app.pcap.upload import (
    PcapUploadInvalid,
    PcapUploadTooLarge,
    PcapUploadUnavailable,
    PcapUploadUnsupported,
)
from app.superagent.models import (
    PcapDetectionMissionRequest,
    PcapReconMissionRequest,
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


def _pcap_recon_unavailable() -> JSONResponse:
    return _error(status_code=503, code="pcap_reconnaissance_unavailable", message="pcap reconnaissance is unavailable")


def _pcap_recon_failed() -> JSONResponse:
    return _error(status_code=500, code="pcap_reconnaissance_failed", message="pcap reconnaissance failed")


def _pcap_detection_unavailable() -> JSONResponse:
    return _error(
        status_code=503,
        code="pcap_detection_unavailable",
        message="pcap detection is unavailable",
    )


def _pcap_detection_failed() -> JSONResponse:
    return _error(
        status_code=500,
        code="pcap_detection_failed",
        message="pcap detection failed",
    )


def _pcap_upload_error(status_code: int, code: str, message: str) -> JSONResponse:
    return _error(status_code=status_code, code=code, message=message)


def _pcap_components(request: Request) -> tuple[Any, Any, Any] | None:
    authorization_store = getattr(
        request.app.state, "pcap_authorization_store", None
    )
    executor = getattr(request.app.state, "pcap_executor", None)
    coordinator = getattr(request.app.state, "pcap_coordinator", None)
    if authorization_store is None or executor is None or coordinator is None:
        return None
    return authorization_store, executor, coordinator


def _pcap_recon_components(request: Request) -> tuple[Any, Any, Any] | None:
    authorization_store = getattr(request.app.state, "pcap_authorization_store", None)
    executor = getattr(request.app.state, "pcap_recon_executor", None)
    coordinator = getattr(request.app.state, "pcap_recon_coordinator", None)
    if authorization_store is None or executor is None or coordinator is None:
        return None
    return authorization_store, executor, coordinator


def _pcap_detection_components(request: Request) -> tuple[Any, Any, Any] | None:
    authorization_store = getattr(request.app.state, "pcap_authorization_store", None)
    executor = getattr(request.app.state, "pcap_detection_executor", None)
    coordinator = getattr(request.app.state, "pcap_detection_coordinator", None)
    if authorization_store is None or executor is None or coordinator is None:
        return None
    return authorization_store, executor, coordinator


def _pcap_upload_components(request: Request) -> tuple[Any, Any, Any, int] | None:
    detection = _pcap_detection_components(request)
    upload_service = getattr(request.app.state, "pcap_upload_service", None)
    upload_max_bytes = getattr(request.app.state, "pcap_upload_max_bytes", None)
    if detection is None or upload_service is None or type(upload_max_bytes) is not int:
        return None
    return detection[0], detection[2], upload_service, upload_max_bytes


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


class _PcapReconAuthorizationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]
    sample_limit: Literal[20]


class _PcapDetectionAuthorizationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]
    max_files: int = Field(ge=1, le=20, strict=True)


class _PcapUploadAuthorizationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]
    byte_count: int = Field(gt=0, strict=True)


@router.get("/pcap/detection/overview")
def pcap_detection_overview(request: Request) -> Any:
    components = _pcap_detection_components(request)
    if components is None:
        return _pcap_detection_unavailable()
    try:
        return components[1].overview()
    except Exception:
        return _pcap_detection_failed()


@router.post("/pcap/detection/authorizations", status_code=201)
def authorize_pcap_detection(
    payload: _PcapDetectionAuthorizationPayload, request: Request
) -> Any:
    components = _pcap_detection_components(request)
    if components is None:
        return _pcap_detection_unavailable()
    try:
        return components[0].issue(payload.max_files, purpose="detection")
    except Exception:
        return _pcap_detection_failed()


@router.get("/pcap/detection/upload-capability")
def pcap_upload_capability(request: Request) -> dict[str, object]:
    components = _pcap_upload_components(request)
    return {
        "enabled": components is not None,
        "max_bytes": components[3] if components is not None else 0,
        "accepted_formats": ["pcap", "pcapng"],
    }


@router.post("/pcap/detection/upload-authorizations", status_code=201)
def authorize_pcap_upload(
    payload: _PcapUploadAuthorizationPayload, request: Request
) -> Any:
    components = _pcap_upload_components(request)
    if components is None:
        return _pcap_upload_error(
            503, "pcap_upload_unavailable", "pcap upload is unavailable"
        )
    authorization_store, _coordinator, _upload_service, upload_max_bytes = components
    if payload.byte_count > upload_max_bytes:
        return _pcap_upload_error(
            413, "pcap_upload_too_large", "pcap upload exceeds the size limit"
        )
    try:
        return authorization_store.issue(
            1,
            purpose="upload_detection",
            expected_byte_count=payload.byte_count,
        )
    except Exception:
        return _pcap_upload_error(500, "pcap_upload_failed", "pcap upload failed")


@router.post("/pcap/detection/uploads", status_code=201)
async def upload_pcap_for_detection(request: Request) -> Any:
    components = _pcap_upload_components(request)
    if components is None:
        return _pcap_upload_error(
            503, "pcap_upload_unavailable", "pcap upload is unavailable"
        )
    authorization_id = request.headers.get("x-pcap-authorization")
    if not authorization_id:
        return _pcap_upload_error(
            403,
            "pcap_authorization_required",
            "pcap authorization is required",
        )
    content_length_text = request.headers.get("content-length", "")
    if not content_length_text.isascii() or not content_length_text.isdecimal():
        return _pcap_upload_error(400, "pcap_upload_invalid", "pcap upload is invalid")
    content_length = int(content_length_text)
    if content_length < 1:
        return _pcap_upload_error(400, "pcap_upload_invalid", "pcap upload is invalid")
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/octet-stream":
        return _pcap_upload_error(
            415, "pcap_format_unsupported", "pcap format is unsupported"
        )

    authorization_store, coordinator, upload_service, upload_max_bytes = components
    if content_length > upload_max_bytes:
        return _pcap_upload_error(
            413, "pcap_upload_too_large", "pcap upload exceeds the size limit"
        )
    try:
        authorization_store.consume(
            authorization_id,
            purpose="upload_detection",
            expected_byte_count=content_length,
        )
        handle = await upload_service.accept(
            request.stream(),
            authorization_id=authorization_id,
            content_length=content_length,
        )
        try:
            return coordinator.start_uploaded(handle)
        except Exception:
            upload_service.discard(handle.handle_id)
            raise
    except PcapAuthorizationPurposeMismatch:
        return _pcap_upload_error(
            403,
            "pcap_authorization_required",
            "pcap authorization is required",
        )
    except PcapAuthorizationUnknown:
        return _pcap_upload_error(
            403,
            "pcap_authorization_required",
            "pcap authorization is required",
        )
    except PcapAuthorizationExpired:
        return _pcap_upload_error(
            410, "pcap_authorization_expired", "pcap authorization expired"
        )
    except PcapAuthorizationAlreadyUsed:
        return _pcap_upload_error(
            409, "pcap_authorization_used", "pcap authorization was already used"
        )
    except PcapUploadTooLarge:
        return _pcap_upload_error(
            413, "pcap_upload_too_large", "pcap upload exceeds the size limit"
        )
    except PcapUploadUnsupported:
        return _pcap_upload_error(
            415, "pcap_format_unsupported", "pcap format is unsupported"
        )
    except (PcapUploadInvalid, ValueError):
        return _pcap_upload_error(400, "pcap_upload_invalid", "pcap upload is invalid")
    except PcapUploadUnavailable:
        return _pcap_upload_error(
            503, "pcap_upload_unavailable", "pcap upload is unavailable"
        )
    except RuntimeError as exc:
        if str(exc) == "pcap_detection_active":
            return _error(
                status_code=409,
                code="pcap_detection_active",
                message="pcap detection is already active",
            )
        return _pcap_upload_error(500, "pcap_upload_failed", "pcap upload failed")
    except Exception:
        return _pcap_upload_error(500, "pcap_upload_failed", "pcap upload failed")


@router.get("/pcap/reconnaissance/overview")
def pcap_reconnaissance_overview(request: Request) -> Any:
    components = _pcap_recon_components(request)
    if components is None:
        return _pcap_recon_unavailable()
    try:
        return components[1].overview()
    except Exception:
        return _pcap_recon_failed()


@router.post("/pcap/reconnaissance/authorizations", status_code=201)
def authorize_pcap_reconnaissance(payload: _PcapReconAuthorizationPayload, request: Request) -> Any:
    components = _pcap_recon_components(request)
    if components is None:
        return _pcap_recon_unavailable()
    try:
        return components[0].issue(payload.sample_limit, purpose="reconnaissance")
    except Exception:
        return _pcap_recon_failed()


@router.post("/missions", status_code=201)
def create_mission(payload: _ApiCreateMissionRequest, request: Request) -> Any:
    if isinstance(payload, PcapDetectionMissionRequest):
        components = _pcap_detection_components(request)
        if components is None:
            return _pcap_detection_unavailable()
        try:
            return components[2].start(payload)
        except PcapAuthorizationPurposeMismatch:
            return _error(status_code=403, code="pcap_authorization_purpose_mismatch", message="pcap authorization purpose mismatch")
        except PcapAuthorizationUnknown:
            return _error(status_code=403, code="pcap_authorization_required", message="pcap authorization is required")
        except PcapAuthorizationExpired:
            return _error(status_code=410, code="pcap_authorization_expired", message="pcap authorization expired")
        except PcapAuthorizationAlreadyUsed:
            return _error(status_code=409, code="pcap_authorization_used", message="pcap authorization was already used")
        except RuntimeError as exc:
            if str(exc) == "pcap_detection_active":
                return _error(status_code=409, code="pcap_detection_active", message="pcap detection is already active")
            return _pcap_detection_failed()
        except Exception:
            return _pcap_detection_failed()
    if isinstance(payload, PcapReconMissionRequest):
        components = _pcap_recon_components(request)
        if components is None:
            return _pcap_recon_unavailable()
        try:
            return components[2].start(payload)
        except PcapAuthorizationPurposeMismatch:
            return _error(status_code=403, code="pcap_authorization_purpose_mismatch", message="pcap authorization purpose mismatch")
        except PcapAuthorizationUnknown:
            return _error(status_code=403, code="pcap_authorization_required", message="pcap authorization is required")
        except PcapAuthorizationExpired:
            return _error(status_code=410, code="pcap_authorization_expired", message="pcap authorization expired")
        except PcapAuthorizationAlreadyUsed:
            return _error(status_code=409, code="pcap_authorization_used", message="pcap authorization was already used")
        except RuntimeError as exc:
            if str(exc) == "pcap_reconnaissance_active":
                return _error(status_code=409, code="pcap_reconnaissance_active", message="pcap reconnaissance is already active")
            return _pcap_recon_failed()
        except Exception:
            return _pcap_recon_failed()
    if isinstance(payload, PcapTriageMissionRequest):
        components = _pcap_components(request)
        if components is None:
            return _pcap_unavailable()
        try:
            return components[2].start(payload)
        except PcapAuthorizationPurposeMismatch:
            return _error(
                status_code=403,
                code="pcap_authorization_purpose_mismatch",
                message="pcap authorization purpose mismatch",
            )
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
        recon_components = _pcap_recon_components(request)
        if components is not None:
            mission_store = components[2].mission_store
        elif recon_components is not None:
            mission_store = recon_components[2].mission_store
        else:
            return _service(request)[1]
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
    recon_components = _pcap_recon_components(request)
    detection_components = _pcap_detection_components(request)
    if mission_id.startswith("detection_"):
        if detection_components is None:
            return _pcap_detection_unavailable()
        try:
            return detection_components[2].cancel(mission_id)
        except (SuperAgentMissionExpired, SuperAgentMissionNotFound):
            return _error(status_code=409, code="pcap_mission_not_cancellable", message="pcap mission is not cancellable")
        except Exception:
            return _pcap_detection_failed()
    if mission_id.startswith("recon_"):
        if recon_components is None:
            return _pcap_recon_unavailable()
        try:
            return recon_components[2].cancel(mission_id)
        except (SuperAgentMissionExpired, SuperAgentMissionNotFound):
            return _error(status_code=409, code="pcap_mission_not_cancellable", message="pcap mission is not cancellable")
        except Exception:
            return _pcap_recon_failed()
    if components is None:
        if recon_components is None:
            return _pcap_unavailable()
        try:
            return recon_components[2].cancel(mission_id)
        except (SuperAgentMissionExpired, SuperAgentMissionNotFound):
            return _error(status_code=409, code="pcap_mission_not_cancellable", message="pcap mission is not cancellable")
        except Exception:
            return _pcap_recon_failed()
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
