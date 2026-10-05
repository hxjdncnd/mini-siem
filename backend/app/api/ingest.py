from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from app.api.deps import SessionDep
from app.ingest import IngestError
from app.schemas import EventIn, IngestResult

router = APIRouter(prefix="/ingest", tags=["ingest"])


async def raw_body(request: Request) -> str:
    """Read the body as text whatever Content-Type the sender used (curl defaults to form-encoded)."""
    return (await request.body()).decode("utf-8", errors="replace")


@router.post("/events", response_model=IngestResult, summary="Ingest pre-structured events (JSON array)")
def ingest_events(request: Request, session: SessionDep, events: Annotated[list[EventIn], Body(min_length=1)]):
    try:
        return request.app.state.ingest.ingest_structured(session, events)
    except IngestError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@router.post(
    "/{log_format}",
    response_model=IngestResult,
    summary="Ingest raw log text, one line per event",
    description="Send the log lines as the request body (`Content-Type: text/plain`). "
    "`log_format` is one of `sshd`, `nginx`, `firewall`.",
)
def ingest_raw(
    log_format: str,
    request: Request,
    session: SessionDep,
    body: Annotated[str, Depends(raw_body)],
    host: Annotated[str | None, Query(max_length=255, description="Machine name, for formats that omit it")] = None,
):
    try:
        return request.app.state.ingest.ingest_raw(session, log_format, body, host)
    except IngestError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
