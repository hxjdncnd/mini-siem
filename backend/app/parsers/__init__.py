from app.parsers.base import LogParser, MalformedLine, ParseContext, ParsedEvent
from app.parsers.firewall import FirewallParser
from app.parsers.nginx import NginxAccessParser
from app.parsers.sshd import SshdAuthParser

# Adding a log source means writing one parser class and registering it here.
PARSERS: dict[str, LogParser] = {p.format: p for p in (SshdAuthParser(), NginxAccessParser(), FirewallParser())}

__all__ = ["PARSERS", "LogParser", "MalformedLine", "ParseContext", "ParsedEvent"]
