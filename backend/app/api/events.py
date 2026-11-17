from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.api.deps import EXPORT_MAX_ROWS, PagingDep, SessionDep, as_utc, csv_response
from app.csvutil import iso
from app.enums import EventAction, SourceType
from app.models import LogEvent
from app.schemas import EventOut, Page
from app.timeutil import from_ms, to_ms

router = APIRouter(prefix="/events", tags=["events"])


class EventFilters:
    """The query parameters shared by the event search and its CSV export."""

    def __init__(
        self,
        source_type: SourceType | None = None,
        action: EventAction | None = None,
        src_ip: str | None = None,
        username: str | None = None,
        host: str | None = None,
        start: Annotated[datetime | None, Query(alias="from", description="Inclusive, ISO-8601")] = None,
        end: Annotated[datetime | None, Query(alias="to", description="Exclusive, ISO-8601")] = None,
        q: Annotated[str | None, Query(max_length=200, description="Substring to find in the raw line")] = None,
    ):
        clauses = []
        if source_type:
            clauses.append(LogEvent.source_type == source_type.value)
        if action:
            clauses.append(LogEvent.action == action.value)
        if src_ip:
            clauses.append(LogEvent.src_ip == src_ip)
        if username:
            clauses.append(LogEvent.username == username)
        if host:
            clauses.append(LogEvent.host == host)
        if start:
            clauses.append(LogEvent.event_time >= to_ms(as_utc(start)))
        if end:
            clauses.append(LogEvent.event_time < to_ms(as_utc(end)))
        if q:
            clauses.append(LogEvent.raw.contains(q, autoescape=True))
        self.clauses = clauses


FiltersDep = Annotated[EventFilters, Depends()]
_ORDER = (LogEvent.event_time.desc(), LogEvent.id)


@router.get("", response_model=Page[EventOut], summary="Search events, newest first")
def search_events(session: SessionDep, paging: PagingDep, f: FiltersDep):
    total = session.scalar(select(func.count()).select_from(LogEvent).where(*f.clauses))
    rows = session.scalars(
        select(LogEvent).where(*f.clauses).order_by(*_ORDER).limit(paging.size).offset(paging.offset)
    )
    return Page(items=[EventOut.of(e) for e in rows], total=total or 0, page=paging.page, size=paging.size)


_EVENT_COLUMNS = (
    "time", "source_type", "action", "host", "src_ip", "dst_ip", "src_port", "dst_port", "username", "protocol",
    "http_method", "http_path", "http_status", "user_agent", "raw",
)  # fmt: skip


@router.get(
    "/export.csv",
    summary="Download events as CSV",
    description=f"Takes the same filters as the search, newest first. At most {EXPORT_MAX_ROWS:,} rows; "
    "the X-Total-Rows header says how many matched.",
    response_class=StreamingResponse,
)
def export_events(request: Request, session: SessionDep, f: FiltersDep):
    total = session.scalar(select(func.count()).select_from(LogEvent).where(*f.clauses)) or 0
    query = select(LogEvent).where(*f.clauses).order_by(*_ORDER).limit(EXPORT_MAX_ROWS)

    def rows():
        with request.app.state.session_factory() as export_session:
            for e in export_session.scalars(query.execution_options(yield_per=1000)):
                yield (
                    iso(from_ms(e.event_time)), e.source_type, e.action, e.host, e.src_ip, e.dst_ip, e.src_port,
                    e.dst_port, e.username, e.protocol, e.http_method, e.http_path, e.http_status, e.user_agent, e.raw,
                )  # fmt: skip

    return csv_response("events", _EVENT_COLUMNS, rows(), total)


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: str, session: SessionDep):
    event = session.get(LogEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"No event with id {event_id}")
    return EventOut.of(event)
