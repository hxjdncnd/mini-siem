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


def auto_bucket(span_seconds: int) -> int:
    """Smallest "nice" bucket that keeps a timeline at 60 points or fewer."""
    for size in (10, 30, 60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 86400, 7 * 86400):
        if span_seconds / size <= 60:
            return size
    return -(-span_seconds // 60)
