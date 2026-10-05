from dataclasses import dataclass
from datetime import datetime, tzinfo
from typing import Protocol

from app.enums import EventAction, SourceType


class MalformedLine(ValueError):
    """The line does not match the log format at all (as opposed to being merely uninteresting)."""


@dataclass(frozen=True)
class ParseContext:
    now: datetime  # timezone-aware; used to infer the year classic syslog leaves out
    default_tz: tzinfo  # assumed when a timestamp has no UTC offset


@dataclass
class ParsedEvent:
    timestamp: datetime
    source_type: SourceType
    action: EventAction
    raw: str
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    username: str | None = None
    protocol: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    user_agent: str | None = None


class LogParser(Protocol):
    #: Name used in the ingest URL, e.g. /api/v1/ingest/sshd
    format: str

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent | None:
        """Return the event, None for a well-formed line with nothing security-relevant in it,
        or raise MalformedLine when the line is not in this format."""
        ...
