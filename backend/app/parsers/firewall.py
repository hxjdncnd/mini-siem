"""UFW / iptables kernel log lines: ``kernel: [UFW BLOCK] IN=eth0 SRC=.. DST=.. PROTO=TCP SPT=.. DPT=..``"""

import re

from app.enums import EventAction, SourceType
from app.parsers.base import MalformedLine, ParseContext, ParsedEvent
from app.parsers.syslog import parse_syslog

_VERDICT = re.compile(r"\[UFW (BLOCK|ALLOW)\]")
_KEY_VALUE = re.compile(r"\b([A-Z]+)=(\S+)")


class FirewallParser:
    format = "firewall"

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent | None:
        header = parse_syslog(line, ctx)
        verdict = _VERDICT.search(header.message)
        if not verdict:
            return None

        fields: dict[str, str] = {}
        for key, value in _KEY_VALUE.findall(header.message):
            fields.setdefault(key, value)
        if "SRC" not in fields or "DST" not in fields:
            raise MalformedLine("Firewall line is missing SRC or DST")

        return ParsedEvent(
            timestamp=header.timestamp,
            source_type=SourceType.FIREWALL,
            action=EventAction.CONN_BLOCKED if verdict.group(1) == "BLOCK" else EventAction.CONN_ALLOWED,
            raw=line,
            host=header.host,
            src_ip=fields["SRC"],
            dst_ip=fields["DST"],
            src_port=_port(fields.get("SPT")),
            dst_port=_port(fields.get("DPT")),
            protocol=fields["PROTO"].lower() if "PROTO" in fields else None,
        )


def _port(value: str | None) -> int | None:
    if value is None:
        return None
    if not value.isdigit() or int(value) > 65535:
        raise MalformedLine(f"Bad port: {value}")
    return int(value)
