"""Linux auth.log / secure: SSH logins and sudo usage."""

import re

from app.enums import EventAction, SourceType
from app.parsers.base import ParseContext, ParsedEvent
from app.parsers.syslog import SyslogHeader, parse_syslog

_FAILED = re.compile(r"^Failed \S+ for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_ACCEPTED = re.compile(r"^Accepted \S+ for (\S+) from (\S+) port (\d+)")
_INVALID_USER = re.compile(r"^Invalid user (\S+) from (\S+)(?: port (\d+))?")
_SUDO = re.compile(r"^\s*(\S+) : .*COMMAND=")

_LOGIN_PATTERNS = (
    (_FAILED, EventAction.LOGIN_FAILURE),
    (_ACCEPTED, EventAction.LOGIN_SUCCESS),
    (_INVALID_USER, EventAction.INVALID_USER),
)


class SshdAuthParser:
    format = "sshd"

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent | None:
        header = parse_syslog(line, ctx)

        if header.program == "sudo":
            m = _SUDO.match(header.message)
            if not m:
                return None
            event = self._base(EventAction.SUDO_COMMAND, header, line)
            event.username = m.group(1)
            return event

        if header.program != "sshd":
            return None

        for pattern, action in _LOGIN_PATTERNS:
            if m := pattern.match(header.message):
                event = self._base(action, header, line)
                event.username = m.group(1)
                event.src_ip = m.group(2)
                event.src_port = int(m.group(3)) if m.group(3) else None
                event.protocol = "ssh"
                return event
        return None

    @staticmethod
    def _base(action: EventAction, header: SyslogHeader, line: str) -> ParsedEvent:
        return ParsedEvent(
            timestamp=header.timestamp, source_type=SourceType.AUTH, action=action, raw=line, host=header.host
        )
