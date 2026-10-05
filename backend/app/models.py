from sqlalchemy import BigInteger, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class LogEvent(Base):
    """A log line normalized into a common shape. Fields a source does not have stay NULL."""

    __tablename__ = "log_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_time: Mapped[int] = mapped_column(BigInteger)
    received_at: Mapped[int] = mapped_column(BigInteger)
    source_type: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(32))
    host: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    username: Mapped[str | None] = mapped_column(String(255))
    protocol: Mapped[str | None] = mapped_column(String(16))
    http_method: Mapped[str | None] = mapped_column(String(16))
    http_path: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("idx_events_time", "event_time"),
        Index("idx_events_src_ip_time", "src_ip", "event_time"),
        Index("idx_events_action_time", "action", "event_time"),
        Index("idx_events_user_time", "username", "event_time"),
    )


# The fields detection rules may filter and group on.
EVENT_FIELDS = frozenset(
    c.name for c in LogEvent.__table__.columns if c.name not in {"id", "event_time", "received_at"}
)


class Alert(Base):
    """One detection: a rule firing for one entity (an IP, a user...) over a stretch of time."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    rule_name: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    # Canonical "field=value,field=value" of the rule's group_by; identifies who the alert is about.
    group_key: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str] = mapped_column(Text)
    mitre: Mapped[str | None] = mapped_column(String(32))
    src_ip: Mapped[str | None] = mapped_column(String(45))
    username: Mapped[str | None] = mapped_column(String(255))
    host: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[int] = mapped_column(BigInteger)
    last_seen: Mapped[int] = mapped_column(BigInteger)
    event_count: Mapped[int] = mapped_column(Integer)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[int] = mapped_column(BigInteger)

    __table_args__ = (
        Index("idx_alerts_rule_group", "rule_id", "group_key", "last_seen"),
        Index("idx_alerts_last_seen", "last_seen"),
        Index("idx_alerts_status", "status"),
    )


class AlertEvent(Base):
    """Evidence: which events an alert was raised on."""

    __tablename__ = "alert_events"

    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("log_events.id", ondelete="CASCADE"), primary_key=True)

    __table_args__ = (Index("idx_alert_events_event", "event_id"),)
