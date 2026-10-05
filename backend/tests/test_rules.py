import pytest

from app.config import Settings
from app.detection.rules import Rule, RuleError, load_rules
from app.models import LogEvent


def event(**fields) -> LogEvent:
    return LogEvent(id="e", event_time=0, received_at=0, source_type="WEB", action="HTTP_REQUEST", **fields)


def rule(**overrides) -> Rule:
    base = dict(id="r", name="R", severity="low", type="match", match={"action": "HTTP_REQUEST"}, group_by=["src_ip"])
    return Rule.model_validate(base | overrides)


def test_shipped_rules_all_load():
    rules = load_rules(Settings(_env_file=None).rules_dir)
    assert len(rules) >= 10
    assert len({r.id for r in rules}) == len(rules)


def test_condition_forms():
    r = rule(
        match={
            "action": "HTTP_REQUEST",  # equality
            "http_status": [403, 404],  # any-of
            "src_port": {"gte": 1024, "lte": 2000},  # range
            "http_method": {"not_in": ["POST"]},
        }
    )
    assert r.matches(event(http_status=404, src_port=1500, http_method="GET"))
    assert not r.matches(event(http_status=200, src_port=1500, http_method="GET"))
    assert not r.matches(event(http_status=404, src_port=80, http_method="GET"))
    assert not r.matches(event(http_status=404, src_port=1500, http_method="POST"))


def test_missing_field_never_matches():
    r = rule(match={"http_method": {"not_in": ["POST"]}})
    assert not r.matches(event(http_method=None))


def test_regex_is_case_insensitive_and_sees_through_url_encoding():
    r = rule(match={"http_path": {"regex": r"union\s+select"}})
    assert r.matches(event(http_path="/item?id=1 UNION SELECT password"))
    assert r.matches(event(http_path="/item?id=1%20union%20select%20password"))
    assert r.matches(event(http_path="/item?id=1+union+select+password"))
    assert not r.matches(event(http_path="/union/selection"))


def test_key_requires_every_group_field():
    r = rule(group_by=["host", "src_ip"])
    assert r.key_of(event(host="web01", src_ip="1.2.3.4")) == ("web01", "1.2.3.4")
    assert r.key_of(event(host="web01", src_ip=None)) is None


@pytest.mark.parametrize(
    "overrides, complaint",
    [
        ({"match": {"colour": "red"}}, "unknown event field"),
        ({"group_by": ["nope"]}, "unknown event fields"),
        ({"type": "threshold"}, "needs"),
        ({"type": "threshold", "window_seconds": 60, "threshold": 5, "distinct_field": "username"}, "does not use"),
        ({"type": "distinct", "window_seconds": 60, "threshold": 5}, "needs"),
        ({"type": "sequence", "threshold": 5, "within_seconds": 60}, "needs"),
        ({"match": {"http_path": {"regex": "("}}}, "bad regex"),
        ({"match": {"http_status": {"between": [1, 2]}}}, "unknown operator"),
        ({"severity": "apocalyptic"}, "severity"),
        ({"id": "Has Spaces"}, "id"),
        ({"threshhold": 5}, "threshhold"),
    ],
)
def test_invalid_rules_are_rejected(overrides, complaint):
    with pytest.raises(ValueError, match=complaint):
        rule(**overrides)


def test_loader_reports_file_and_rule(tmp_path):
    (tmp_path / "bad.yml").write_text(
        "- id: broken\n  name: Broken\n  severity: low\n  type: threshold\n  match: {action: X}\n  group_by: [src_ip]\n"
    )
    with pytest.raises(RuleError, match=r"bad\.yml: rule 'broken'"):
        load_rules(tmp_path)


def test_loader_rejects_duplicate_ids(tmp_path):
    one = "id: same\nname: A\nseverity: low\ntype: match\nmatch: {action: X}\ngroup_by: [src_ip]\n"
    (tmp_path / "a.yml").write_text(one)
    (tmp_path / "b.yaml").write_text(one)
    with pytest.raises(RuleError, match="duplicate rule id 'same'"):
        load_rules(tmp_path)
