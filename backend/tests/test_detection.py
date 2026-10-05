"""Behaviour of the detection engine, driven through the real API: raw log lines in, alerts out."""

import random
import sys
from datetime import UTC, datetime, timedelta

import pytest

from app.detection.engine import risk_score
from app.enums import Severity
from tests.conftest import REPO_ROOT, alerts_by_rule, post_log

sys.path.insert(0, str(REPO_ROOT / "simulator"))
import simulate  # noqa: E402

T0 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)
ATTACKER = "203.0.113.50"


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def failures(count: int, *, start: float = 0, every: float = 2, ip: str = ATTACKER, user: str = "root") -> str:
    return "\n".join(simulate._failed(at(start + i * every), user, ip) for i in range(count))


def blocked(ports, *, start: float = 0, ip: str = ATTACKER) -> str:
    return "\n".join(simulate._ufw(at(start + i * 0.1), "BLOCK", ip, port) for i, port in enumerate(ports))


class TestThreshold:
    def test_below_threshold_is_quiet(self, client):
        result = post_log(client, "sshd", failures(4))
        assert result["alerts_created"] == 0
        assert alerts_by_rule(client) == {}

    def test_reaching_threshold_raises_one_alert_with_its_evidence(self, client):
        result = post_log(client, "sshd", failures(5))
        assert result["alerts_created"] == 1

        (alert,) = alerts_by_rule(client)["ssh-brute-force"]
        assert alert["severity"] == "high"
        assert alert["src_ip"] == ATTACKER
        assert alert["event_count"] == 5
        assert alert["summary"] == f"5 failed SSH logins from {ATTACKER}"
        assert alert["mitre"] == "T1110.001"
        assert alert["first_seen"] == "2026-10-05T12:00:00Z"
        assert alert["last_seen"] == "2026-10-05T12:00:08Z"

    def test_slow_failures_outside_the_window_are_quiet(self, client):
        post_log(client, "sshd", failures(8, every=20))  # never 5 inside any 60 seconds
        assert "ssh-brute-force" not in alerts_by_rule(client)

    def test_counts_are_per_source_address(self, client):
        lines = [failures(3, ip="203.0.113.1"), failures(3, ip="203.0.113.2")]
        post_log(client, "sshd", "\n".join(lines))
        assert alerts_by_rule(client) == {}

    def test_ongoing_attack_extends_the_alert_instead_of_opening_new_ones(self, client):
        post_log(client, "sshd", failures(6))
        second = post_log(client, "sshd", failures(10, start=20))
        assert (second["alerts_created"], second["alerts_updated"]) == (0, 1)

        (alert,) = alerts_by_rule(client)["ssh-brute-force"]
        assert alert["event_count"] == 16
        assert alert["last_seen"] == "2026-10-05T12:00:38Z"

    def test_separate_bursts_are_separate_alerts(self, client):
        post_log(client, "sshd", failures(6) + "\n" + failures(6, start=3 * 3600))
        alerts = alerts_by_rule(client)["ssh-brute-force"]
        assert sorted(a["event_count"] for a in alerts) == [6, 6]

    def test_attack_resuming_after_triage_raises_a_fresh_alert(self, client):
        post_log(client, "sshd", failures(6))
        (first,) = alerts_by_rule(client)["ssh-brute-force"]
        client.patch(f"/api/v1/alerts/{first['id']}", json={"status": "RESOLVED"})

        result = post_log(client, "sshd", failures(6, start=30))
        assert result["alerts_created"] == 1
        statuses = sorted(a["status"] for a in alerts_by_rule(client)["ssh-brute-force"])
        assert statuses == ["OPEN", "RESOLVED"]

    def test_events_arriving_out_of_order_still_add_up(self, client):
        assert post_log(client, "sshd", failures(3, start=10))["alerts_created"] == 0
        # An earlier slice of the same burst shows up late (a delayed log shipper).
        assert post_log(client, "sshd", failures(2, start=0))["alerts_created"] == 1
        (alert,) = alerts_by_rule(client)["ssh-brute-force"]
        assert alert["event_count"] == 5

    def test_unrelated_batches_do_not_touch_existing_alerts(self, client):
        post_log(client, "sshd", failures(6))
        result = post_log(client, "sshd", failures(1, ip="198.51.100.7", start=5))
        assert (result["alerts_created"], result["alerts_updated"]) == (0, 0)


class TestDistinct:
    def test_many_hits_on_one_port_is_not_a_scan(self, client):
        post_log(client, "firewall", blocked([22] * 30))
        assert "port-scan" not in alerts_by_rule(client)

    def test_many_different_ports_is_a_scan(self, client):
        assert post_log(client, "firewall", blocked(range(20, 29)))["alerts_created"] == 0  # 9 ports
        post_log(client, "firewall", blocked([29], start=1))  # the 10th
        (alert,) = alerts_by_rule(client)["port-scan"]
        assert alert["event_count"] == 10
        assert alert["severity"] == "medium"

    def test_allowed_connections_do_not_count(self, client):
        lines = "\n".join(simulate._ufw(at(i), "ALLOW", ATTACKER, 8000 + i) for i in range(20))
        post_log(client, "firewall", lines)
        assert alerts_by_rule(client) == {}

    def test_password_spray_counts_usernames_not_attempts(self, client):
        post_log(client, "sshd", failures(4, user="root", every=20))  # 4 tries, 1 username, slow
        assert alerts_by_rule(client) == {}
        users = ["admin", "test", "oracle", "git", "pi"]
        lines = "\n".join(simulate._failed(at(200 + i * 20), u, ATTACKER) for i, u in enumerate(users))
        post_log(client, "sshd", lines)
        assert set(alerts_by_rule(client)) == {"password-spray"}


class TestSequence:
    def success(self, seconds: float, ip: str = ATTACKER) -> str:
        return simulate._accepted(at(seconds), "root", ip, method="password")

    def test_success_after_failures_is_critical(self, client):
        post_log(client, "sshd", failures(5, every=20) + "\n" + self.success(150))
        (alert,) = alerts_by_rule(client)["ssh-brute-force-success"]
        assert alert["severity"] == "critical"
        assert alert["score"] >= 90
        detail = client.get(f"/api/v1/alerts/{alert['id']}").json()
        assert [e["action"] for e in detail["events"]] == ["LOGIN_FAILURE"] * 5 + ["LOGIN_SUCCESS"]

    def test_success_arriving_in_a_later_batch_still_completes_the_sequence(self, client):
        post_log(client, "sshd", failures(5, every=20))
        assert post_log(client, "sshd", self.success(150))["alerts_created"] >= 1
        assert "ssh-brute-force-success" in alerts_by_rule(client)

    def test_success_long_after_the_failures_is_unrelated(self, client):
        post_log(client, "sshd", failures(5, every=20) + "\n" + self.success(2000))
        assert "ssh-brute-force-success" not in alerts_by_rule(client)

    def test_success_from_another_address_is_unrelated(self, client):
        post_log(client, "sshd", failures(5, every=20) + "\n" + self.success(150, ip="198.51.100.7"))
        assert "ssh-brute-force-success" not in alerts_by_rule(client)

    def test_too_few_failures_before_success(self, client):
        post_log(client, "sshd", failures(4, every=20) + "\n" + self.success(150))
        assert "ssh-brute-force-success" not in alerts_by_rule(client)


class TestMatch:
    def request(self, seconds: float, path: str, agent: str = "Mozilla/5.0", ip: str = ATTACKER) -> str:
        return simulate._nginx(at(seconds), ip, "GET", path, 200, agent)

    def test_repeat_hits_collapse_into_one_alert_per_attacker(self, client):
        lines = [self.request(i, f"/item?id={i}%20UNION%20SELECT%20password%20FROM%20users") for i in range(4)]
        lines.append(self.request(9, "/item?id=1%27%20OR%20%271%27=%271", ip="203.0.113.200"))
        post_log(client, "nginx", "\n".join(lines))
        alerts = {a["src_ip"]: a for a in alerts_by_rule(client)["web-sql-injection"]}
        assert alerts[ATTACKER]["event_count"] == 4
        assert alerts[ATTACKER]["summary"] == f"SQL injection attempts from {ATTACKER} (4 requests)"
        assert alerts["203.0.113.200"]["event_count"] == 1

    @pytest.mark.parametrize("path", ["/search?q=union+station+select+seats", "/products/drop-tables", "/docs/..info"])
    def test_innocent_paths_do_not_trip_signatures(self, client, path):
        post_log(client, "nginx", self.request(0, path))
        assert alerts_by_rule(client) == {}


def test_risk_score_bands_and_volume_bonus():
    assert risk_score(Severity.LOW, 1, 1) == 20
    assert risk_score(Severity.HIGH, 5, 5) == 70
    assert risk_score(Severity.HIGH, 40, 5) == 76  # 8x the threshold = 3 doublings
    assert risk_score(Severity.HIGH, 10**6, 5) == 80  # bonus is capped
    assert risk_score(Severity.CRITICAL, 10**6, 1) == 100


class TestSimulator:
    """The simulator is the demo, so the suite guarantees every scenario does what it advertises."""

    @pytest.mark.parametrize("name", list(simulate.SCENARIOS))
    def test_scenario_trips_exactly_its_expected_rules(self, client, name):
        random.seed(7)
        for batch in simulate.SCENARIOS[name](T0):
            result = post_log(client, batch.log_format, "\n".join(batch.lines), host=simulate.HOST)
            assert result["failed"] == 0, result["errors"]
        assert set(alerts_by_rule(client)) == simulate.EXPECTED_ALERTS[name]

    def test_full_run_matches_the_sum_of_its_parts(self, client):
        random.seed(7)
        names = list(simulate.SCENARIOS)
        for _name, batch in simulate.build(names, T0, spread_minutes=90):
            post_log(client, batch.log_format, "\n".join(batch.lines), host=simulate.HOST)
        expected = set().union(*simulate.EXPECTED_ALERTS.values())
        assert set(alerts_by_rule(client)) == expected

        stats = client.get(
            "/api/v1/stats/summary",
            params={
                "from": (T0 - timedelta(minutes=91)).isoformat(),
                "to": (T0 + timedelta(minutes=1)).isoformat(),
            },
        ).json()
        assert stats["total_events"] >= 250
        assert stats["open_alerts"] == stats["total_alerts"] >= len(expected)
