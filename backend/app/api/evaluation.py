from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.evaluation.service import EvaluationSummary


router = APIRouter(prefix="/api/v1", tags=["evaluation"])


@router.get("/evaluation/summary", response_model=EvaluationSummary)
def evaluation_summary(request: Request) -> EvaluationSummary:
    service = getattr(request.app.state, "evaluation_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="evaluation report is unavailable")
    active_version = getattr(request.app.state, "active_calibration_version", None)
    return service.load(active_calibration_version=active_version)
