"""Timestamps are stored as UTC epoch milliseconds: sortable, portable, and easy to bucket in SQL."""

from datetime import UTC, datetime


def to_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return round(dt.timestamp() * 1000)


def from_ms(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


def now_ms() -> int:
    return to_ms(datetime.now(UTC))
