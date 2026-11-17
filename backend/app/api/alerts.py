from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import case, func, select

from app.api.deps import EXPORT_MAX_ROWS, PagingDep, SessionDep, as_utc, csv_response
from app.csvutil import iso
from app.enums import ACTIVE_STATUSES, AlertStatus, Severity
from app.models import Alert, AlertEvent, LogEvent
from app.schemas import AlertDetail, AlertOut, AlertUpdate, EventOut, Page
from app.timeutil import from_ms, now_ms, to_ms

router = APIRouter(prefix="/alerts", tags=["alerts"])

_MAX_EVIDENCE = 200
_SEVERITY_RANK = case(
    {s.value: rank for rank, s in enumerate([Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])},
    value=Alert.severity,
    else_=-1,
)


class AlertFilters:
    """The query parameters shared by the alert list and its CSV export."""

    def __init__(
        self,
        status: AlertStatus | None = None,
        active: Annotated[bool | None, Query(description="true = only OPEN and ACKNOWLEDGED")] = None,
        severity: Severity | None = None,
        min_severity: Severity | None = None,
        rule_id: str | None = None,
        src_ip: str | None = None,
        username: str | None = None,
        host: str | None = None,
        start: Annotated[datetime | None, Query(alias="from", description="last_seen at or after")] = None,
        end: Annotated[datetime | None, Query(alias="to", description="first_seen before")] = None,
        sort: Annotated[str, Query(pattern="^(recent|score)$")] = "recent",
    ):
        clauses = []
        if status:
            clauses.append(Alert.status == status.value)
        if active is not None:
            active_values = [s.value for s in ACTIVE_STATUSES]
            clauses.append(Alert.status.in_(active_values) if active else Alert.status.not_in(active_values))
        if severity:
            clauses.append(Alert.severity == severity.value)
        if min_severity:
            ranks = list(Severity)
            clauses.append(Alert.severity.in_([s.value for s in ranks[ranks.index(min_severity) :]]))
        if rule_id:
            clauses.append(Alert.rule_id == rule_id)
        if src_ip:
            clauses.append(Alert.src_ip == src_ip)
        if username:
            clauses.append(Alert.username == username)
        if host:
            clauses.append(Alert.host == host)
        if start:
            clauses.append(Alert.last_seen >= to_ms(as_utc(start)))
        if end:
            clauses.append(Alert.first_seen < to_ms(as_utc(end)))
        self.clauses = clauses
        self.order = (
            (Alert.score.desc(), Alert.last_seen.desc(), Alert.id)
            if sort == "score"
            else (Alert.last_seen.desc(), _SEVERITY_RANK.desc(), Alert.id)
        )


FiltersDep = Annotated[AlertFilters, Depends()]


@router.get("", response_model=Page[AlertOut], summary="List alerts")
def list_alerts(session: SessionDep, paging: PagingDep, f: FiltersDep):
    total = session.scalar(select(func.count()).select_from(Alert).where(*f.clauses))
    rows = session.scalars(select(Alert).where(*f.clauses).order_by(*f.order).limit(paging.size).offset(paging.offset))
    return Page(items=[AlertOut.of(a) for a in rows], total=total or 0, page=paging.page, size=paging.size)


_ALERT_COLUMNS = (
    "id", "rule_id", "rule_name", "severity", "score", "status", "summary", "mitre", "src_ip", "username",
    "host", "first_seen", "last_seen", "event_count", "note", "created_at",
)  # fmt: skip


@router.get(
    "/export.csv",
    summary="Download alerts as CSV",
    description=f"Takes the same filters and sort as the list. At most {EXPORT_MAX_ROWS:,} rows; "
    "the X-Total-Rows header says how many matched.",
    response_class=StreamingResponse,
)
def export_alerts(request: Request, session: SessionDep, f: FiltersDep):
    total = session.scalar(select(func.count()).select_from(Alert).where(*f.clauses)) or 0
    query = select(Alert).where(*f.clauses).order_by(*f.order).limit(EXPORT_MAX_ROWS)

    def rows():
        with request.app.state.session_factory() as export_session:
            for a in export_session.scalars(query.execution_options(yield_per=1000)):
                yield (
                    a.id, a.rule_id, a.rule_name, a.severity, a.score, a.status, a.summary, a.mitre, a.src_ip,
                    a.username, a.host, iso(from_ms(a.first_seen)), iso(from_ms(a.last_seen)), a.event_count,
                    a.note, iso(from_ms(a.created_at)),
                )  # fmt: skip

    return csv_response("alerts", _ALERT_COLUMNS, rows(), total)


@router.get("/{alert_id}", response_model=AlertDetail, summary="One alert with its evidence events")
def get_alert(alert_id: str, session: SessionDep):
    alert = _get_or_404(session, alert_id)
    events = session.scalars(
        select(LogEvent)
        .join(AlertEvent, AlertEvent.event_id == LogEvent.id)
        .where(AlertEvent.alert_id == alert_id)
        .order_by(LogEvent.event_time, LogEvent.id)
        .limit(_MAX_EVIDENCE)
    )
    return AlertDetail(**AlertOut.of(alert).model_dump(), events=[EventOut.of(e) for e in events])


@router.patch("/{alert_id}", response_model=AlertOut, summary="Triage: change status and/or leave a note")
def update_alert(alert_id: str, update: AlertUpdate, session: SessionDep):
    alert = _get_or_404(session, alert_id)
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Provide 'status' and/or 'note'")
    if changes.get("status") is not None:
        alert.status = update.status.value
    if "note" in changes:
        alert.note = update.note
    alert.updated_at = now_ms()
    session.commit()
    return AlertOut.of(alert)


def _get_or_404(session, alert_id: str) -> Alert:
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
    return alert
