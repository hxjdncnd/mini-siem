"""Investigation views: everything the platform knows about one entity."""

import ipaddress
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from app.api.deps import SessionDep
from app.models import Alert, LogEvent
from app.schemas import AlertOut, CountBy, EventOut, IpClassification, IpProfile, TimeBucket
from app.timeutil import auto_bucket, from_ms

router = APIRouter(prefix="/ips", tags=["entities"])

# Ranges reserved for examples and documentation (RFC 5737, RFC 3849). Python lumps them in with "private",
# but they are what test data and tutorials use, so say so.
_DOCUMENTATION = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]

_LABELS = {
    "documentation": "Documentation range (reserved for examples and test data)",
    "loopback": "Loopback (the machine itself)",
    "link_local": "Link-local (same network segment only)",
    "multicast": "Multicast",
    "reserved": "Reserved or unspecified address",
    "private": "Private network address (internal)",
    "public": "Public internet address",
}
_INTERNAL = {"loopback", "link_local", "private"}


def classify(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> IpClassification:
    if any(addr in net for net in _DOCUMENTATION):
        kind = "documentation"
    elif addr.is_loopback:
        kind = "loopback"
    elif addr.is_link_local:
        kind = "link_local"
    elif addr.is_multicast:
        kind = "multicast"
    elif addr.is_unspecified or addr.is_reserved:
        kind = "reserved"
    elif addr.is_private:
        kind = "private"
    else:
        kind = "public"
    return IpClassification(kind=kind, label=_LABELS[kind], internal=kind in _INTERNAL)


@router.get("/{ip}", response_model=IpProfile, summary="Everything seen from one source address")
def ip_profile(ip: str, session: SessionDep, top: Annotated[int, Query(ge=1, le=50)] = 10):
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{ip}' is not a valid IP address") from None
    ip_text = str(addr)  # canonical spelling, so "::1" and "0:0:0:0:0:0:0:1" are the same address

    mine = LogEvent.src_ip == ip_text
    total = session.scalar(select(func.count()).select_from(LogEvent).where(mine)) or 0
    alerts = session.scalars(
        select(Alert)
        .where(Alert.src_ip == ip_text)
        .order_by(Alert.score.desc(), Alert.last_seen.desc(), Alert.id)
        .limit(50)
    ).all()
    if total == 0 and not alerts:
        raise HTTPException(status_code=404, detail=f"No activity recorded from {ip_text}")

    first, last = session.execute(
        select(func.min(LogEvent.event_time), func.max(LogEvent.event_time)).where(mine)
    ).one()

    def top_counts(column) -> list[CountBy]:
        query = (
            select(column, func.count().label("n"))
            .where(mine, column.is_not(None))
            .group_by(column)
            .order_by(func.count().desc(), column)
            .limit(top)
        )
        return [CountBy(key=str(key), count=n) for key, n in session.execute(query)]

    timeline: list[TimeBucket] = []
    bucket_seconds = 1
    if first is not None:
        lo, hi = first, last + 1
        bucket_seconds = auto_bucket(max(1, (hi - lo) // 1000))
        bucket_ms = bucket_seconds * 1000
        bucket = (LogEvent.event_time - lo) // bucket_ms
        filled = {
            int(k): n for k, n in session.execute(select(bucket.label("b"), func.count()).where(mine).group_by("b"))
        }
        bucket_count = -(-(hi - lo) // bucket_ms)
        timeline = [TimeBucket(start=from_ms(lo + i * bucket_ms), count=filled.get(i, 0)) for i in range(bucket_count)]

    recent = session.scalars(select(LogEvent).where(mine).order_by(LogEvent.event_time.desc(), LogEvent.id).limit(20))
    return IpProfile(
        ip=ip_text,
        classification=classify(addr),
        event_count=total,
        first_seen=from_ms(first) if first is not None else None,
        last_seen=from_ms(last) if last is not None else None,
        hosts=top_counts(LogEvent.host),
        actions=top_counts(LogEvent.action),
        usernames=top_counts(LogEvent.username),
        http_paths=top_counts(LogEvent.http_path),
        dst_ports=top_counts(LogEvent.dst_port),
        events_over_time=timeline,
        bucket_seconds=bucket_seconds,
        alerts=[AlertOut.of(a) for a in alerts],
        max_score=max((a.score for a in alerts), default=0),
        recent_events=[EventOut.of(e) for e in recent],
    )
