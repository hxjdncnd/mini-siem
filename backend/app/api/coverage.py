"""Which ATT&CK techniques the loaded rules cover, and where the gaps are."""

from fastapi import APIRouter, Request
from sqlalchemy import case, func, select

from app.api.deps import SessionDep
from app.enums import ACTIVE_STATUSES
from app.mitre import SUGGESTED, TACTICS, TECHNIQUES
from app.models import Alert
from app.schemas import Coverage, CoverageRule, CoverageTactic, CoverageTechnique

router = APIRouter(prefix="/coverage", tags=["coverage"])

_UNMAPPED = ("-", "Unmapped")


@router.get(
    "",
    response_model=Coverage,
    summary="ATT&CK techniques covered by the loaded rules, grouped by tactic",
    description="A technique counts as covered when at least one rule is tagged with it, whether or not that rule "
    "is switched on (each rule says which). Techniques the rules do not cover yet are listed from a hand-picked "
    "set, not the full matrix.",
)
def coverage(request: Request, session: SessionDep):
    rules = request.app.state.rules
    active = [s.value for s in ACTIVE_STATUSES]
    per_rule = {
        rule_id: (count, running)
        for rule_id, count, running in session.execute(
            select(Alert.rule_id, func.count(), func.sum(case((Alert.status.in_(active), 1), else_=0))).group_by(
                Alert.rule_id
            )
        )
    }

    by_technique: dict[str, list] = {}
    for rule in rules:
        if rule.mitre:
            by_technique.setdefault(rule.mitre, []).append(rule)

    def technique(technique_id: str) -> CoverageTechnique:
        covering = by_technique.get(technique_id, [])
        counts = [per_rule.get(rule.id, (0, 0)) for rule in covering]
        name = TECHNIQUES.get(technique_id, (technique_id, []))[0]
        return CoverageTechnique(
            id=technique_id,
            name=name,
            covered=bool(covering),
            rules=[CoverageRule(id=r.id, name=r.name, severity=r.severity, enabled=r.enabled) for r in covering],
            alert_count=sum(count for count, _ in counts),
            active_alerts=sum(int(running or 0) for _, running in counts),
        )

    shown = [t for t in TECHNIQUES if t in by_technique or t in SUGGESTED]
    placed: dict[str, list[CoverageTechnique]] = {tactic_id: [] for tactic_id, _ in TACTICS}
    for technique_id in shown:
        for tactic_id in TECHNIQUES[technique_id][1]:
            placed[tactic_id].append(technique(technique_id))
    unmapped = [technique(t) for t in by_technique if t not in TECHNIQUES]

    tactics = [
        CoverageTactic(id=tactic_id, name=name, techniques=sorted(placed[tactic_id], key=_order))
        for tactic_id, name in TACTICS
        if placed[tactic_id]
    ]
    if unmapped:
        tactics.append(CoverageTactic(id=_UNMAPPED[0], name=_UNMAPPED[1], techniques=sorted(unmapped, key=_order)))

    return Coverage(
        tactics=tactics,
        techniques_covered=len(by_technique),
        rules_total=len(rules),
        rules_enabled=sum(1 for rule in rules if rule.enabled),
        rules_untagged=[rule.id for rule in rules if not rule.mitre],
    )


def _order(item: CoverageTechnique) -> tuple[int, str]:
    return (0 if item.covered else 1, item.id)
