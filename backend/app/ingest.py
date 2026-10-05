import uuid
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.config import Settings
from app.detection.engine import DetectionEngine
from app.models import LogEvent
from app.parsers import PARSERS, MalformedLine, ParseContext, ParsedEvent
from app.schemas import EventIn, IngestResult, LineError
from app.timeutil import to_ms

_MAX_REPORTED_ERRORS = 20


class IngestError(ValueError):
    """The request as a whole is unusable (unknown format, too large)."""


class IngestService:
    def __init__(self, settings: Settings, engine: DetectionEngine):
        self.settings = settings
        self.engine = engine
        self.default_tz = ZoneInfo(settings.default_timezone)

    def ingest_raw(self, session: Session, log_format: str, body: str, fallback_host: str | None) -> IngestResult:
        """Parse a block of raw log text, one event per line. A bad line never rejects the whole
        batch: it is counted and reported, and the good lines are still stored.

        fallback_host is used when the format itself does not name the machine (access logs).
        """
        parser = PARSERS.get(log_format)
        if parser is None:
            raise IngestError(f"Unknown log format '{log_format}'. Supported: {sorted(PARSERS)}")
        lines = body.splitlines()
        self._check_size(len(lines), "lines")

        now = datetime.now(UTC)
        ctx = ParseContext(now=now, default_tz=self.default_tz)
        events: list[LogEvent] = []
        errors: list[LineError] = []
        received = skipped = failed = 0

        for number, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            received += 1
            try:
                parsed = parser.parse(line, ctx)
            except MalformedLine as e:
                failed += 1
                if len(errors) < _MAX_REPORTED_ERRORS:
                    errors.append(LineError(line=number, reason=str(e)))
                continue
            if parsed is None:
                skipped += 1
            else:
                events.append(_to_model(parsed, now, fallback_host))

        return self._store(session, events, received=received, skipped=skipped, failed=failed, errors=errors)

    def ingest_structured(self, session: Session, items: list[EventIn]) -> IngestResult:
        self._check_size(len(items), "events")
        now = datetime.now(UTC)
        events = [
            LogEvent(
                id=str(uuid.uuid4()),
                event_time=to_ms(item.timestamp or now),
                received_at=to_ms(now),
                **item.model_dump(exclude={"timestamp"}, mode="json"),
            )
            for item in items
        ]
        return self._store(session, events, received=len(items), skipped=0, failed=0, errors=[])

    def _store(self, session: Session, events: list[LogEvent], **counts) -> IngestResult:
        session.add_all(events)
        session.flush()
        outcome = self.engine.evaluate(session, events)
        session.commit()  # events and the alerts they caused land together or not at all
        return IngestResult(
            stored=len(events), alerts_created=len(outcome.created), alerts_updated=len(outcome.updated), **counts
        )

    def _check_size(self, count: int, what: str) -> None:
        if count > self.settings.max_lines_per_request:
            raise IngestError(f"Too many {what} in one request (max {self.settings.max_lines_per_request})")


def _to_model(parsed: ParsedEvent, now: datetime, fallback_host: str | None) -> LogEvent:
    return LogEvent(
        id=str(uuid.uuid4()),
        event_time=to_ms(parsed.timestamp),
        received_at=to_ms(now),
        source_type=parsed.source_type.value,
        action=parsed.action.value,
        host=parsed.host or fallback_host,
        src_ip=parsed.src_ip,
        dst_ip=parsed.dst_ip,
        src_port=parsed.src_port,
        dst_port=parsed.dst_port,
        username=parsed.username,
        protocol=parsed.protocol,
        http_method=parsed.http_method,
        http_path=parsed.http_path,
        http_status=parsed.http_status,
        user_agent=parsed.user_agent,
        raw=parsed.raw,
    )
