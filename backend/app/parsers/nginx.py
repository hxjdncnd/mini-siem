"""nginx / Apache "combined" access log format."""

import re
from datetime import datetime

from app.enums import EventAction, SourceType
from app.parsers.base import MalformedLine, ParseContext, ParsedEvent

# 203.0.113.9 - alice [05/Oct/2026:14:02:11 +0000] "GET /login HTTP/1.1" 200 512 "-" "curl/8.4"
_LINE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) (?:\d+|-)'
    r'(?: "[^"]*" "([^"]*)")?'
)


class NginxAccessParser:
    format = "nginx"

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent | None:
        m = _LINE.match(line)
        if not m:
            raise MalformedLine("Not a combined-format access log line")
        try:
            timestamp = datetime.strptime(m.group(3), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            raise MalformedLine(f"Unreadable timestamp: {m.group(3)}") from None
        return ParsedEvent(
            timestamp=timestamp,
            source_type=SourceType.WEB,
            action=EventAction.HTTP_REQUEST,
            raw=line,
            src_ip=m.group(1),
            username=None if m.group(2) == "-" else m.group(2),
            protocol="http",
            http_method=m.group(4),
            http_path=m.group(5),
            http_status=int(m.group(6)),
            user_agent=m.group(7),
        )
