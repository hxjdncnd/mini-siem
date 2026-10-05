"""Turns stored events into alerts.

The engine runs after every ingest batch, but it reasons in *event time*, not wall-clock time:
it looks at which entities (IPs, users...) the new events touch, reloads that entity's recent
history from the database, and re-scans it. That makes it correct for historical log files and
for events that arrive out of order, and it means the engine keeps no state in memory.
"""

import math
import uuid
from collections import Counter
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.rules import Rule
from app.enums import ACTIVE_STATUSES, AlertStatus, Severity
from app.models import Alert, AlertEvent, LogEvent
from app.timeutil import now_ms

_SEVERITY_BASE = {Severity.LOW: 20, Severity.MEDIUM: 40, Severity.HIGH: 70, Severity.CRITICAL: 90}
_ENTITY_FIELDS = ("src_ip", "username", "host")


@dataclass
class EvaluationResult:
    created: list[Alert] = field(default_factory=list)
    updated: list[Alert] = field(default_factory=list)


def risk_score(severity: Severity, event_count: int, threshold: int) -> int:
    """0-100. Severity sets the band; sustained volume nudges it up (+2 per doubling, capped at +10)."""
    doublings = int(math.log2(max(1.0, event_count / max(1, threshold))))
    return min(100, _SEVERITY_BASE[severity] + min(10, 2 * doublings))


class DetectionEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = [r for r in rules if r.enabled]

    def evaluate(self, session: Session, new_events: list[LogEvent]) -> EvaluationResult:
        run = _Run(session)
        if new_events:
            for rule in self.rules:
                match rule.type:
                    case "match":
                        _eval_match(run, rule, new_events)
                    case "threshold" | "distinct":
                        _eval_windowed(run, rule, new_events)
                    case "sequence":
                        _eval_sequence(run, rule, new_events)
        return run.result()


def _eval_match(run: "_Run", rule: Rule, new_events: list[LogEvent]) -> None:
    by_key: dict[tuple, list[LogEvent]] = {}
    for event in new_events:
        if rule.matches(event) and (key := rule.key_of(event)) is not None:
            by_key.setdefault(key, []).append(event)
    for key, events in by_key.items():
        # Split into bursts so two visits a day apart become two alerts, not one.
        events.sort(key=_order)
        burst = [events[0]]
        for event in events[1:]:
            if event.event_time - burst[-1].event_time > rule.suppress_ms:
                run.raise_alert(rule, key, burst)
                burst = []
            burst.append(event)
        run.raise_alert(rule, key, burst)


def _eval_windowed(run: "_Run", rule: Rule, new_events: list[LogEvent]) -> None:
    for key, (lo, hi) in _touched(rule, new_events, rule.matches).items():
        events = [
            e for e in run.load(rule, key, lo - rule.window_ms, hi + rule.window_ms, prefilter=True) if rule.matches(e)
        ]
        if rule.type == "distinct":
            events = [e for e in events if getattr(e, rule.distinct_field) is not None]
        _scan_window(run, rule, key, events)


def _scan_window(run: "_Run", rule: Rule, key: tuple, events: list[LogEvent]) -> None:
    """Two-pointer sliding window over time-sorted events. While the condition keeps holding the
    burst keeps growing, so one sustained attack is reported once with all of its evidence."""
    values: Counter = Counter()
    start = 0
    burst_start: int | None = None
    burst_end = 0

    def value_of(e: LogEvent):
        return getattr(e, rule.distinct_field) if rule.type == "distinct" else e.id

    for end, event in enumerate(events):
        values[value_of(event)] += 1
        while event.event_time - events[start].event_time > rule.window_ms:
            old = value_of(events[start])
            values[old] -= 1
            if values[old] == 0:
                del values[old]
            start += 1

        if len(values) >= rule.threshold:
            if burst_start is None:
                burst_start = start
            burst_end = end
        elif burst_start is not None:
            run.raise_alert(rule, key, events[burst_start : burst_end + 1])
            burst_start = None

    if burst_start is not None:
        run.raise_alert(rule, key, events[burst_start : burst_end + 1])


def _eval_sequence(run: "_Run", rule: Rule, new_events: list[LogEvent]) -> None:
    def relevant(e: LogEvent) -> bool:
        return rule.matches(e) or rule.then_matches(e)

    for key, (lo, hi) in _touched(rule, new_events, relevant).items():
        history = run.load(rule, key, lo - rule.within_ms, hi + rule.within_ms, prefilter=False)
        lead_up = [e for e in history if rule.matches(e)]
        for outcome in (e for e in history if rule.then_matches(e)):
            before = [e for e in lead_up if outcome.event_time - rule.within_ms <= e.event_time <= outcome.event_time]
            if len(before) >= rule.threshold:
                run.raise_alert(rule, key, [*before, outcome])


def _touched(rule: Rule, new_events: list[LogEvent], relevant) -> dict[tuple, tuple[int, int]]:
    """Entities the new events concern, each with the time span those events cover."""
    spans: dict[tuple, tuple[int, int]] = {}
    for event in new_events:
        if relevant(event) and (key := rule.key_of(event)) is not None:
            lo, hi = spans.get(key, (event.event_time, event.event_time))
            spans[key] = (min(lo, event.event_time), max(hi, event.event_time))
    return spans


def _order(event: LogEvent) -> tuple[int, str]:
    return (event.event_time, event.id)


def _key_string(rule: Rule, key: tuple) -> str:
    return ",".join(f"{name}={value}" for name, value in zip(rule.group_by, key, strict=True))


class _Run:
    """State for one evaluation pass: caches, and the bookkeeping of what was created vs. extended."""

    def __init__(self, session: Session):
        self.session = session
        self._current: dict[tuple[str, str], Alert] = {}
        self._links: dict[str, set[str]] = {}
        self._created: dict[str, Alert] = {}
        self._updated: dict[str, Alert] = {}

    def result(self) -> EvaluationResult:
        self.session.flush()
        return EvaluationResult(list(self._created.values()), list(self._updated.values()))

    def load(self, rule: Rule, key: tuple, lo: int, hi: int, *, prefilter: bool) -> list[LogEvent]:
        query = select(LogEvent).where(LogEvent.event_time >= lo, LogEvent.event_time <= hi)
        for name, value in zip(rule.group_by, key, strict=True):
            query = query.where(getattr(LogEvent, name) == value)
        if prefilter:
            query = query.where(*rule.sql_prefilter())
        return list(self.session.scalars(query.order_by(LogEvent.event_time, LogEvent.id)))

    def raise_alert(self, rule: Rule, key: tuple, events: list[LogEvent]) -> None:
        first = min(e.event_time for e in events)
        last = max(e.event_time for e in events)
        key_string = _key_string(rule, key)

        alert = self._find_active(rule, key_string, first, last)
        if alert is None:
            now = now_ms()
            entity = dict(zip(rule.group_by, key, strict=True))
            alert = Alert(
                id=str(uuid.uuid4()),
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity.value,
                score=0,
                status=AlertStatus.OPEN.value,
                group_key=key_string,
                summary="",
                mitre=rule.mitre,
                first_seen=first,
                last_seen=last,
                event_count=0,
                created_at=now,
                updated_at=now,
                **{f: str(entity[f]) for f in _ENTITY_FIELDS if f in entity},
            )
            self.session.add(alert)
            self._links[alert.id] = set()
            self._created[alert.id] = alert
        self._current[(rule.id, key_string)] = alert

        links = self._linked_event_ids(alert)
        added = [e for e in events if e.id not in links]
        if not added and alert.id not in self._created:
            return  # re-scan of evidence this alert already has: nothing changed
        for event in added:
            self.session.add(AlertEvent(alert_id=alert.id, event_id=event.id))
            links.add(event.id)
        if alert.id not in self._created:
            self._updated[alert.id] = alert

        alert.first_seen = min(alert.first_seen, first)
        alert.last_seen = max(alert.last_seen, last)
        alert.event_count = len(links)
        alert.score = risk_score(rule.severity, alert.event_count, rule.threshold or 1)
        alert.summary = _summarize(rule, key, alert.event_count)
        alert.updated_at = now_ms()

    def _find_active(self, rule: Rule, key_string: str, first: int, last: int) -> Alert | None:
        """Deduplication: an open alert for the same rule and entity that this evidence overlaps or
        closely follows. Resolved alerts are left alone, so a repeat after triage raises a fresh one."""
        lo, hi = first - rule.suppress_ms, last + rule.suppress_ms
        cached = self._current.get((rule.id, key_string))
        if cached is not None and cached.last_seen >= lo and cached.first_seen <= hi:
            return cached
        return self.session.scalars(
            select(Alert)
            .where(
                Alert.rule_id == rule.id,
                Alert.group_key == key_string,
                Alert.status.in_([s.value for s in ACTIVE_STATUSES]),
                Alert.last_seen >= lo,
                Alert.first_seen <= hi,
            )
            .order_by(Alert.last_seen.desc())
            .limit(1)
        ).first()

    def _linked_event_ids(self, alert: Alert) -> set[str]:
        if alert.id not in self._links:
            self._links[alert.id] = set(
                self.session.scalars(select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id))
            )
        return self._links[alert.id]


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _summarize(rule: Rule, key: tuple, count: int) -> str:
    values = _SafeDict(zip(rule.group_by, key, strict=True))
    values["count"] = count
    template = rule.summary or (rule.name + " ({" + "}, {".join(rule.group_by) + "})")
    try:
        return template.format_map(values)
    except (ValueError, IndexError):
        return f"{rule.name} ({_key_string(rule, key)})"
