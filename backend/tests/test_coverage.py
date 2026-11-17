"""The ATT&CK coverage map: what the rules cover, where the gaps are."""

from app.detection.rules import load_rules
from app.mitre import SUGGESTED, TACTICS, TECHNIQUES
from tests.conftest import REPO_ROOT, post_log
from tests.test_detection import failures
from tests.test_respond import BRUTE_FORCE_SUCCESS


def technique(coverage: dict, technique_id: str, tactic_id: str | None = None) -> dict:
    matches = [
        t
        for tactic in coverage["tactics"]
        if tactic_id in (None, tactic["id"])
        for t in tactic["techniques"]
        if t["id"] == technique_id
    ]
    assert matches, f"{technique_id} is not on the map"
    return matches[0]


class TestCatalog:
    def test_every_shipped_rule_is_tagged_with_a_technique_the_catalog_knows(self):
        """Adding a rule with a new tag fails here until mitre.py learns it, so the map never silently drops one."""
        rules = load_rules(REPO_ROOT / "backend" / "rules")
        assert all(rule.mitre for rule in rules), "every shipped rule should carry a MITRE tag"
        assert {rule.mitre for rule in rules} <= set(TECHNIQUES)

    def test_the_catalog_is_internally_consistent(self):
        tactic_ids = {tactic_id for tactic_id, _ in TACTICS}
        for technique_id, (name, tactics) in TECHNIQUES.items():
            assert tactics and set(tactics) <= tactic_ids, technique_id
            assert technique_id.startswith("T") and name, technique_id
            if "." in technique_id:  # a sub-technique is named "Parent: Child"
                assert ": " in name, technique_id
        assert set(TECHNIQUES) >= SUGGESTED


class TestCoverageEndpoint:
    def test_lists_covered_techniques_under_their_tactics(self, client):
        coverage = client.get("/api/v1/coverage").json()
        guessing = technique(coverage, "T1110.001", "TA0006")
        assert guessing["name"] == "Brute Force: Password Guessing"
        assert guessing["covered"] is True
        assert [r["id"] for r in guessing["rules"]] == ["ssh-brute-force"]

    def test_a_technique_in_several_tactics_appears_in_each(self, client):
        coverage = client.get("/api/v1/coverage").json()
        tactics = {t["id"] for t in coverage["tactics"] if any(x["id"] == "T1078" for x in t["techniques"])}
        assert tactics == {"TA0001", "TA0003", "TA0004", "TA0005"}

    def test_suggested_gaps_are_shown_as_uncovered(self, client):
        coverage = client.get("/api/v1/coverage").json()
        gap = technique(coverage, "T1136", "TA0003")
        assert (gap["covered"], gap["rules"], gap["alert_count"]) == (False, [], 0)

    def test_covered_techniques_come_before_gaps_within_a_tactic(self, client):
        for tactic in client.get("/api/v1/coverage").json()["tactics"]:
            flags = [t["covered"] for t in tactic["techniques"]]
            assert flags == sorted(flags, reverse=True), tactic["id"]

    def test_counts_for_the_summary(self, client):
        coverage = client.get("/api/v1/coverage").json()
        assert coverage["rules_total"] == 11
        assert coverage["rules_enabled"] == 11
        assert coverage["rules_untagged"] == []
        assert coverage["techniques_covered"] == 11  # the distinct MITRE tags across the shipped rules

    def test_alerts_are_attributed_to_the_technique_of_their_rule(self, client):
        post_log(client, "sshd", BRUTE_FORCE_SUCCESS)
        coverage = client.get("/api/v1/coverage").json()
        guessing = technique(coverage, "T1110.001")
        assert (guessing["alert_count"], guessing["active_alerts"]) == (1, 1)
        success = technique(coverage, "T1110")
        assert success["alert_count"] == 1
        assert technique(coverage, "T1046")["alert_count"] == 0

        alert_id = client.get("/api/v1/alerts", params={"rule_id": "ssh-brute-force"}).json()["items"][0]["id"]
        client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "RESOLVED"})
        guessing = technique(client.get("/api/v1/coverage").json(), "T1110.001")
        assert (guessing["alert_count"], guessing["active_alerts"]) == (1, 0)  # resolved alerts stop counting as active

    def test_a_switched_off_rule_still_counts_as_coverage_but_says_it_is_off(self, client):
        client.patch("/api/v1/rules/port-scan", json={"enabled": False})
        coverage = client.get("/api/v1/coverage").json()
        scan = technique(coverage, "T1046")
        assert scan["covered"] is True
        assert [(r["id"], r["enabled"]) for r in scan["rules"]] == [("port-scan", False)]
        assert coverage["rules_enabled"] == 10

    def test_nothing_changes_when_events_arrive_without_alerts(self, client):
        before = client.get("/api/v1/coverage").json()
        post_log(client, "sshd", failures(2))
        assert client.get("/api/v1/coverage").json() == before
