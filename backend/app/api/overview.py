"""Read-only views for the dashboard: loaded rules and aggregate statistics."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, select

from app.api.deps import SessionDep, as_utc
from app.enums import ACTIVE_STATUSES
from app.models import Alert, LogEvent
from app.schemas import CountBy, RuleOut, StatsSummary, TimeBucket
from app.timeutil import from_ms, to_ms

router = APIRouter(tags=["overview"])

_MAX_BUCKETS = 500


@router.get("/rules", response_model=list[RuleOut], summary="Detection rules currently loaded")
def list_rules(request: Request, session: SessionDep):
    counts = dict(session.execute(select(Alert.rule_id, func.count()).group_by(Alert.rule_id)).all())
    return [
        RuleOut(
            **rule.model_dump(include=set(RuleOut.model_fields) - {"alert_count"}), alert_count=counts.get(rule.id, 0)
        )
        for rule in request.app.state.rules
    ]


@router.get(
    "/stats/summary",
    response_model=StatsSummary,
    response_model_by_alias=True,
    summary="Counts and a timeline for a time range (default: the last 24 hours)",
)
def stats_summary(
    session: SessionDep,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    bucket_seconds: Annotated[
        int | None, Query(ge=1, description="Timeline bucket; chosen automatically if omitted")
    ] = None,
    top: Annotated[int, Query(ge=1, le=50)] = 10,
):
    end = as_utc(end) or datetime.now(UTC)
    start = as_utc(start) or end - timedelta(hours=24)
    if start >= end:
        raise HTTPException(status_code=400, detail="'from' must be before 'to'")
    lo, hi = to_ms(start), to_ms(end)
    span_seconds = max(1, (hi - lo) // 1000)
    if bucket_seconds is None:
        bucket_seconds = _auto_bucket(span_seconds)
    elif span_seconds / bucket_seconds > _MAX_BUCKETS:
        raise HTTPException(
            status_code=400, detail=f"bucket_seconds too small for this range (max {_MAX_BUCKETS} buckets)"
        )

    in_range = (LogEvent.event_time >= lo, LogEvent.event_time < hi)

    def event_counts(column, limit: int | None = None) -> list[CountBy]:
        query = (
            select(column, func.count().label("n"))
            .where(*in_range, column.is_not(None))
            .group_by(column)
            .order_by(func.count().desc(), column)
        )
        if limit:
            query = query.limit(limit)
        return [CountBy(key=str(k), count=n) for k, n in session.execute(query)]

    # Epoch-millisecond integers make time bucketing plain integer division, identical on SQLite and Postgres.
    bucket_ms = bucket_seconds * 1000
    bucket = (LogEvent.event_time - lo) // bucket_ms
    filled = dict(session.execute(select(bucket.label("b"), func.count()).where(*in_range).group_by("b")).all())
    filled = {int(k): n for k, n in filled.items()}
    bucket_count = -(-(hi - lo) // bucket_ms)
    timeline = [TimeBucket(start=from_ms(lo + i * bucket_ms), count=filled.get(i, 0)) for i in range(bucket_count)]

    alert_range = (Alert.last_seen >= lo, Alert.first_seen < hi)

    def alert_counts(column) -> list[CountBy]:
        query = select(column, func.count()).where(*alert_range).group_by(column).order_by(func.count().desc(), column)
        return [CountBy(key=str(k), count=n) for k, n in session.execute(query)]

    by_status = alert_counts(Alert.status)
    active = {s.value for s in ACTIVE_STATUSES}
    return StatsSummary(
        range_start=start,
        range_end=end,
        total_events=session.scalar(select(func.count()).select_from(LogEvent).where(*in_range)) or 0,
        events_by_source=event_counts(LogEvent.source_type),
        events_by_action=event_counts(LogEvent.action),
        top_source_ips=event_counts(LogEvent.src_ip, limit=top),
        events_over_time=timeline,
        bucket_seconds=bucket_seconds,
        total_alerts=sum(c.count for c in by_status),
        open_alerts=sum(c.count for c in by_status if c.key in active),
        alerts_by_severity=alert_counts(Alert.severity),
        alerts_by_status=by_status,
        alerts_by_rule=alert_counts(Alert.rule_id),
    )


def _auto_bucket(span_seconds: int) -> int:
    """Smallest "nice" bucket that keeps the timeline at 60 points or fewer."""
    for size in (10, 30, 60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 86400, 7 * 86400):
        if span_seconds / size <= 60:
            return size
    return -(-span_seconds // 60)
