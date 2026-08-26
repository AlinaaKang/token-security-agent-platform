from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.demo.service import (
    DemoAnalysisResult,
    DemoSampleNotFound,
    DemoSampleSummary,
)


router = APIRouter(prefix="/api/v1", tags=["demo"])


@router.get("/demo-samples", response_model=list[DemoSampleSummary])
def list_demo_samples(
    request: Request,
    family: str | None = None,
    limit: int = Query(default=30, ge=1, le=100),
) -> list[DemoSampleSummary]:
    service = getattr(request.app.state, "demo_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="demo samples are unavailable")
    return service.list_samples(family=family, limit=limit)


@router.post(
    "/demo-samples/{sample_id}/analyze", response_model=DemoAnalysisResult
)
def analyze_demo_sample(sample_id: str, request: Request) -> DemoAnalysisResult:
    service = getattr(request.app.state, "demo_service", None)
    workflow = getattr(request.app.state, "analysis_workflow", None)
    if service is None or workflow is None:
        raise HTTPException(status_code=503, detail="demo samples are unavailable")
    try:
        return service.analyze(sample_id, workflow)
    except DemoSampleNotFound:
        raise HTTPException(status_code=404, detail="demo sample was not found") from None
