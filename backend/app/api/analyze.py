from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.schemas import AnalysisRequest
from app.audit.models import SecurityEvent


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/v1", tags=["analysis"])


def _error_response(
    *, request_id: str, status_code: int, code: str, message: str
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "request_id": request_id,
            "error": {"code": code, "message": message},
        },
    )


@router.post("/analyze")
def analyze(payload: AnalysisRequest, request: Request) -> Any:
    request_id = f"req_{uuid.uuid4().hex}"
    workflow = getattr(request.app.state, "analysis_workflow", None)
    if workflow is None:
        return _error_response(
            request_id=request_id,
            status_code=503,
            code="model_unavailable",
            message="model and detector services are not ready",
        )
    result = workflow.analyze(payload, request_id=request_id)
    store = getattr(request.app.state, "event_store", None)
    if store is None:
        return result

    thresholds = result.provenance.thresholds
    try:
        store.append(
            SecurityEvent(
                request_id=result.request_id,
                created_at=datetime.now(UTC),
                prompt_sha256=(
                    "sha256:"
                    + hashlib.sha256(payload.prompt.encode("utf-8")).hexdigest()
                ),
                prompt_char_count=len(payload.prompt),
                token_count=len(result.signals),
                detector_score=result.detector_score,
                k=thresholds["k"],
                h=thresholds["h"],
                onset_token=(
                    result.suspicious_span.token_start
                    if result.suspicious_span is not None
                    else None
                ),
                detector_status=result.detector_status,
                decision=result.decision,
                mode=payload.mode,
                model_id=result.provenance.model_id,
                calibration_version=result.provenance.calibration_version,
                latency_ms=result.latency_ms,
                semantic_severity=result.semantic_severity,
                semantic_categories=result.semantic_categories,
                semantic_model_id=result.semantic_model_id,
                semantic_model_version=result.semantic_model_version,
                semantic_latency_ms=result.semantic_latency_ms,
                fusion_reason=result.fusion_reason,
                knowledge_snapshot_version=result.knowledge_snapshot_version,
                knowledge_mode=payload.knowledge_mode,
                knowledge_status=result.knowledge_status,
                knowledge_card_ids=[
                    item.knowledge_id for item in result.knowledge_evidence
                ],
                report_status=result.report_status,
                knowledge_latency_ms=result.knowledge_latency_ms,
            )
        )
    except Exception as exc:
        logger.error(
            "event audit write failed request_id=%s error_type=%s",
            request_id,
            type(exc).__name__,
        )
        return result
    return result.model_copy(update={"audit_persisted": True})
