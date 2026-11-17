"""Detection rules: list them, switch them on and off, and try one against the events already stored."""

import logging

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select

from app.api.deps import SessionDep
from app.detection.rules import Rule
from app.models import Alert, LogEvent, RuleState
from app.schemas import RuleOut, RuleTestFinding, RuleTestResult, RuleUpdate
from app.timeutil import from_ms, now_ms

router = APIRouter(prefix="/rules", tags=["rules"])
log = logging.getLogger("minisiem")

# A dry run replays the most recent events only, so it stays quick on a large database.
TEST_MAX_EVENTS = 50_000
_TEST_MAX_FINDINGS = 25


def _rule_out(rule: Rule, alert_count: int) -> RuleOut:
    return RuleOut(**rule.model_dump(include=set(RuleOut.model_fields) - {"alert_count"}), alert_count=alert_count)


def _find(request: Request, rule_id: str) -> Rule:
    for rule in request.app.state.rules:
        if rule.id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail=f"No rule with id {rule_id}")


@router.get("", response_model=list[RuleOut], summary="Detection rules currently loaded")
def list_rules(request: Request, session: SessionDep):
    counts = dict(session.execute(select(Alert.rule_id, func.count()).group_by(Alert.rule_id)).all())
    return [_rule_out(rule, counts.get(rule.id, 0)) for rule in request.app.state.rules]


@router.patch(
    "/{rule_id}",
    response_model=RuleOut,
    summary="Switch a rule on or off",
    description="Takes effect on the next batch of events and survives a restart. "
    "Alerts the rule has already raised are left as they are.",
)
def update_rule(rule_id: str, update: RuleUpdate, request: Request, session: SessionDep):
    rule = _find(request, rule_id)
    state = session.get(RuleState, rule_id)
    if state is None:
        session.add(RuleState(rule_id=rule_id, enabled=update.enabled, updated_at=now_ms()))
    else:
        state.enabled, state.updated_at = update.enabled, now_ms()
    session.commit()
    if rule.enabled != update.enabled:
        log.info("Rule %s %s", rule_id, "enabled" if update.enabled else "disabled")
    rule.enabled = update.enabled
    count = session.scalar(select(func.count()).select_from(Alert).where(Alert.rule_id == rule_id)) or 0
    return _rule_out(rule, count)


@router.post(
    "/{rule_id}/test",
    response_model=RuleTestResult,
    summary="Dry run: what would this rule raise over the stored events?",
    description=f"Replays up to the {TEST_MAX_EVENTS:,} most recent events through the rule, whether or not it is "
    "enabled, without creating or changing any alert.",
)
def test_rule(rule_id: str, request: Request, session: SessionDep):
    rule = _find(request, rule_id)
    total = session.scalar(select(func.count()).select_from(LogEvent)) or 0
    events = list(session.scalars(select(LogEvent).order_by(LogEvent.event_time.desc()).limit(TEST_MAX_EVENTS)))
    events.reverse()
    would = request.app.state.ingest.engine.preview(session, rule, events)
    would.sort(key=lambda a: (-a.score, -a.last_seen))
    already = session.scalar(select(func.count()).select_from(Alert).where(Alert.rule_id == rule_id)) or 0
    return RuleTestResult(
        rule_id=rule_id,
        enabled=rule.enabled,
        events_scanned=len(events),
        events_total=total,
        scanned_from=from_ms(events[0].event_time) if events else None,
        scanned_to=from_ms(events[-1].event_time) if events else None,
        would_raise=len(would),
        already_raised=already,
        findings=[
            RuleTestFinding(
                summary=a.summary,
                severity=a.severity,
                score=a.score,
                group_key=a.group_key,
                src_ip=a.src_ip,
                username=a.username,
                host=a.host,
                first_seen=from_ms(a.first_seen),
                last_seen=from_ms(a.last_seen),
                event_count=a.event_count,
            )
            for a in would[:_TEST_MAX_FINDINGS]
        ],
    )
