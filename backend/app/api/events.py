from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.audit.models import EventPage
from app.schemas import Decision, DetectorStatus


router = APIRouter(prefix="/api/v1", tags=["events"])


@router.get("/events", response_model=EventPage)
def list_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    decision: Decision | None = None,
    detector_status: DetectorStatus | None = None,
) -> EventPage:
    store = getattr(request.app.state, "event_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="event audit is unavailable")
    return store.list_events(
        limit=limit,
        offset=offset,
        decision=decision,
        detector_status=detector_status,
    )
