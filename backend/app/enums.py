from enum import StrEnum


class SourceType(StrEnum):
    """Which kind of log an event came from."""

    AUTH = "AUTH"
    WEB = "WEB"
    FIREWALL = "FIREWALL"


class EventAction(StrEnum):
    """What happened, in one vocabulary shared by every log source. Detection rules key off this."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    INVALID_USER = "INVALID_USER"
    SUDO_COMMAND = "SUDO_COMMAND"
    HTTP_REQUEST = "HTTP_REQUEST"
    CONN_BLOCKED = "CONN_BLOCKED"
    CONN_ALLOWED = "CONN_ALLOWED"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


ACTIVE_STATUSES = (AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED)
