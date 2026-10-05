"""The "when / which machine / which program" prefix shared by sshd, sudo and kernel firewall lines."""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.parsers.base import MalformedLine, ParseContext

# Oct  5 14:02:11 web01 sshd[812]: message
_CLASSIC = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) ([^\s:\[]+)(?:\[\d+\])?: (.*)$")
# 2026-10-05T14:02:11.123456-04:00 web01 sshd[812]: message   (newer rsyslog / journald)
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\S+) (\S+) ([^\s:\[]+)(?:\[\d+\])?: (.*)$")


@dataclass(frozen=True)
class SyslogHeader:
    timestamp: datetime
    host: str
    program: str
    message: str


def parse_syslog(line: str, ctx: ParseContext) -> SyslogHeader:
    if m := _ISO.match(line):
        try:
            ts = datetime.fromisoformat(m.group(1))
        except ValueError:
            raise MalformedLine(f"Unreadable timestamp: {m.group(1)}") from None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=ctx.default_tz)
        return SyslogHeader(ts, m.group(2), m.group(3), m.group(4))

    if m := _CLASSIC.match(line):
        ts = _resolve_year(m.group(1), m.group(2), m.group(3), ctx)
        return SyslogHeader(ts, m.group(4), m.group(5), m.group(6))

    raise MalformedLine("Not a syslog line")


def _resolve_year(month: str, day: str, time: str, ctx: ParseContext) -> datetime:
    """Classic syslog omits the year. Assume the current one, falling back to last year when
    that would land in the future (a December line read in January)."""
    now = ctx.now.astimezone(ctx.default_tz)

    def with_year(year: int) -> datetime:
        try:
            parsed = datetime.strptime(f"{year} {month} {day} {time}", "%Y %b %d %H:%M:%S")
        except ValueError:
            raise MalformedLine(f"Unreadable timestamp: {month} {day} {time}") from None
        return parsed.replace(tzinfo=ctx.default_tz)

    candidate = with_year(now.year)
    if candidate > now + timedelta(days=1):
        candidate = with_year(now.year - 1)
    return candidate
