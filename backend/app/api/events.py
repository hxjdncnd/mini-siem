from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from app.api.deps import PagingDep, SessionDep, as_utc
from app.enums import EventAction, SourceType
from app.models import LogEvent
from app.schemas import EventOut, Page
from app.timeutil import to_ms

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=Page[EventOut], summary="Search events, newest first")
def search_events(
    session: SessionDep,
    paging: PagingDep,
    source_type: SourceType | None = None,
    action: EventAction | None = None,
    src_ip: str | None = None,
    username: str | None = None,
    host: str | None = None,
    start: Annotated[datetime | None, Query(alias="from", description="Inclusive, ISO-8601")] = None,
    end: Annotated[datetime | None, Query(alias="to", description="Exclusive, ISO-8601")] = None,
    q: Annotated[str | None, Query(max_length=200, description="Substring to find in the raw line")] = None,
):
    filters = []
    if source_type:
        filters.append(LogEvent.source_type == source_type.value)
    if action:
        filters.append(LogEvent.action == action.value)
    if src_ip:
        filters.append(LogEvent.src_ip == src_ip)
    if username:
        filters.append(LogEvent.username == username)
    if host:
        filters.append(LogEvent.host == host)
    if start:
        filters.append(LogEvent.event_time >= to_ms(as_utc(start)))
    if end:
        filters.append(LogEvent.event_time < to_ms(as_utc(end)))
    if q:
        filters.append(LogEvent.raw.contains(q, autoescape=True))

    total = session.scalar(select(func.count()).select_from(LogEvent).where(*filters))
    rows = session.scalars(
        select(LogEvent)
        .where(*filters)
        .order_by(LogEvent.event_time.desc(), LogEvent.id)
        .limit(paging.size)
        .offset(paging.offset)
    )
    return Page(items=[EventOut.of(e) for e in rows], total=total or 0, page=paging.page, size=paging.size)


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: str, session: SessionDep):
    event = session.get(LogEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"No event with id {event_id}")
    return EventOut.of(event)
