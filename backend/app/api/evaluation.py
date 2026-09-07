from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.evaluation.service import EvaluationSummary
from app.evaluation.pcap_detection import PcapEvaluationSummary


router = APIRouter(prefix="/api/v1", tags=["evaluation"])


@router.get("/evaluation/summary", response_model=EvaluationSummary)
def evaluation_summary(request: Request) -> EvaluationSummary:
    service = getattr(request.app.state, "evaluation_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="evaluation report is unavailable")
    active_version = getattr(request.app.state, "active_calibration_version", None)
    return service.load(active_calibration_version=active_version)


@router.get("/evaluation/pcap-summary", response_model=PcapEvaluationSummary)
def pcap_evaluation_summary(request: Request) -> PcapEvaluationSummary:
    summary = getattr(request.app.state, "pcap_evaluation_summary", None)
    if summary is None:
        raise HTTPException(status_code=503, detail="pcap evaluation report is unavailable")
    return summary
