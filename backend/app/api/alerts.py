from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import case, func, select

from app.api.deps import PagingDep, SessionDep, as_utc
from app.enums import ACTIVE_STATUSES, AlertStatus, Severity
from app.models import Alert, AlertEvent, LogEvent
from app.schemas import AlertDetail, AlertOut, AlertUpdate, EventOut, Page
from app.timeutil import now_ms, to_ms

router = APIRouter(prefix="/alerts", tags=["alerts"])

_MAX_EVIDENCE = 200
_SEVERITY_RANK = case(
    {s.value: rank for rank, s in enumerate([Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])},
    value=Alert.severity,
    else_=-1,
)


@router.get("", response_model=Page[AlertOut], summary="List alerts")
def list_alerts(
    session: SessionDep,
    paging: PagingDep,
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
    filters = []
    if status:
        filters.append(Alert.status == status.value)
    if active is not None:
        active_values = [s.value for s in ACTIVE_STATUSES]
        filters.append(Alert.status.in_(active_values) if active else Alert.status.not_in(active_values))
    if severity:
        filters.append(Alert.severity == severity.value)
    if min_severity:
        ranks = list(Severity)
        filters.append(Alert.severity.in_([s.value for s in ranks[ranks.index(min_severity) :]]))
    if rule_id:
        filters.append(Alert.rule_id == rule_id)
    if src_ip:
        filters.append(Alert.src_ip == src_ip)
    if username:
        filters.append(Alert.username == username)
    if host:
        filters.append(Alert.host == host)
    if start:
        filters.append(Alert.last_seen >= to_ms(as_utc(start)))
    if end:
        filters.append(Alert.first_seen < to_ms(as_utc(end)))

    order = (
        (Alert.score.desc(), Alert.last_seen.desc(), Alert.id)
        if sort == "score"
        else (Alert.last_seen.desc(), _SEVERITY_RANK.desc(), Alert.id)
    )
    total = session.scalar(select(func.count()).select_from(Alert).where(*filters))
    rows = session.scalars(select(Alert).where(*filters).order_by(*order).limit(paging.size).offset(paging.offset))
    return Page(items=[AlertOut.of(a) for a in rows], total=total or 0, page=paging.page, size=paging.size)


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
