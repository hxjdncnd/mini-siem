"""Shapes of the JSON the API accepts and returns."""

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

from app.enums import AlertStatus, EventAction, Severity, SourceType
from app.models import Alert, LogEvent
from app.timeutil import from_ms

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int


class EventOut(BaseModel):
    id: str
    timestamp: datetime
    received_at: datetime
    source_type: SourceType
    action: EventAction
    host: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    username: str | None
    protocol: str | None
    http_method: str | None
    http_path: str | None
    http_status: int | None
    user_agent: str | None
    raw: str | None

    @classmethod
    def of(cls, e: LogEvent) -> "EventOut":
        return cls(
            id=e.id,
            timestamp=from_ms(e.event_time),
            received_at=from_ms(e.received_at),
            source_type=e.source_type,
            action=e.action,
            host=e.host,
            src_ip=e.src_ip,
            dst_ip=e.dst_ip,
            src_port=e.src_port,
            dst_port=e.dst_port,
            username=e.username,
            protocol=e.protocol,
            http_method=e.http_method,
            http_path=e.http_path,
            http_status=e.http_status,
            user_agent=e.user_agent,
            raw=e.raw,
        )


class EventIn(BaseModel):
    """An already-structured event, for senders that do their own parsing."""

    timestamp: datetime | None = None
    source_type: SourceType
    action: EventAction
    host: str | None = Field(default=None, max_length=255)
    src_ip: str | None = Field(default=None, max_length=45)
    dst_ip: str | None = Field(default=None, max_length=45)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    username: str | None = Field(default=None, max_length=255)
    protocol: str | None = Field(default=None, max_length=16)
    http_method: str | None = Field(default=None, max_length=16)
    http_path: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    user_agent: str | None = None
    raw: str | None = None


class LineError(BaseModel):
    line: int
    reason: str


class IngestResult(BaseModel):
    received: int = Field(description="Lines (or events) in the request, ignoring blank lines")
    stored: int = Field(description="Events written to the database")
    skipped: int = Field(description="Well-formed lines with nothing security-relevant in them")
    failed: int = Field(description="Lines that did not match the format")
    errors: list[LineError] = Field(description="The first few failures, to help debug a log shipper")
    alerts_created: int
    alerts_updated: int


class AlertOut(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    score: int
    status: AlertStatus
    summary: str
    group_key: str
    mitre: str | None
    src_ip: str | None
    username: str | None
    host: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    note: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def of(cls, a: Alert) -> "AlertOut":
        return cls(
            id=a.id,
            rule_id=a.rule_id,
            rule_name=a.rule_name,
            severity=a.severity,
            score=a.score,
            status=a.status,
            summary=a.summary,
            group_key=a.group_key,
            mitre=a.mitre,
            src_ip=a.src_ip,
            username=a.username,
            host=a.host,
            first_seen=from_ms(a.first_seen),
            last_seen=from_ms(a.last_seen),
            event_count=a.event_count,
            note=a.note,
            created_at=from_ms(a.created_at),
            updated_at=from_ms(a.updated_at),
        )


class AlertDetail(AlertOut):
    events: list[EventOut] = Field(description="Evidence, oldest first (capped; event_count is the true total)")


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    note: str | None = Field(default=None, max_length=2000)


class RuleOut(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    type: str
    group_by: list[str]
    window_seconds: int | None
    threshold: int | None
    distinct_field: str | None
    within_seconds: int | None
    mitre: str | None
    enabled: bool
    alert_count: int


class CountBy(BaseModel):
    key: str
    count: int


class TimeBucket(BaseModel):
    start: datetime
    count: int


class StatsSummary(BaseModel):
    range_start: datetime = Field(alias="from")
    range_end: datetime = Field(alias="to")
    total_events: int
    events_by_source: list[CountBy]
    events_by_action: list[CountBy]
    top_source_ips: list[CountBy]
    events_over_time: list[TimeBucket]
    bucket_seconds: int
    total_alerts: int
    open_alerts: int
    alerts_by_severity: list[CountBy]
    alerts_by_status: list[CountBy]
    alerts_by_rule: list[CountBy]

    model_config = {"populate_by_name": True}
