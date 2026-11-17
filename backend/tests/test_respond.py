"""Acting on detections: switching rules off, dry-running a rule, webhook notifications and CSV export."""

import csv
import hashlib
import hmac
import io
import json
import queue
import random
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import REPO_ROOT, alerts_by_rule, post_log
from tests.test_detection import ATTACKER, T0, at, failures

sys.path.insert(0, str(REPO_ROOT / "simulator"))
import simulate  # noqa: E402

# Six failures ten seconds apart (enough for the brute-force rule), then a password login that works.
BRUTE_FORCE_SUCCESS = failures(6, every=10) + "\n" + simulate._accepted(at(65), "root", ATTACKER, method="password")


def total_alerts(client) -> int:
    return client.get("/api/v1/alerts").json()["total"]


class TestSwitchingRules:
    def test_a_disabled_rule_stops_raising_alerts_and_can_be_turned_back_on(self, client):
        response = client.patch("/api/v1/rules/ssh-brute-force", json={"enabled": False})
        assert response.status_code == 200
        assert response.json()["enabled"] is False

        post_log(client, "sshd", failures(8))
        assert "ssh-brute-force" not in alerts_by_rule(client)

        client.patch("/api/v1/rules/ssh-brute-force", json={"enabled": True})
        post_log(client, "sshd", failures(8, start=3600))
        assert "ssh-brute-force" in alerts_by_rule(client)

    def test_the_choice_survives_a_restart(self, settings):
        with TestClient(create_app(settings)) as first:
            first.patch("/api/v1/rules/port-scan", json={"enabled": False})
        with TestClient(create_app(settings)) as second:
            rules = {r["id"]: r["enabled"] for r in second.get("/api/v1/rules").json()}
            assert rules["port-scan"] is False
            assert rules["ssh-brute-force"] is True

    def test_existing_alerts_are_left_alone(self, client):
        post_log(client, "sshd", failures(8))
        before = total_alerts(client)
        client.patch("/api/v1/rules/ssh-brute-force", json={"enabled": False})
        assert total_alerts(client) == before

    def test_unknown_rule_and_bad_body(self, client):
        assert client.patch("/api/v1/rules/nope", json={"enabled": False}).status_code == 404
        assert client.patch("/api/v1/rules/ssh-brute-force", json={}).status_code == 422
        assert client.patch("/api/v1/rules/ssh-brute-force", json={"enabled": "maybe"}).status_code == 422


class TestDryRun:
    def test_reports_what_would_fire_and_writes_nothing(self, client):
        client.patch("/api/v1/rules/ssh-brute-force", json={"enabled": False})
        post_log(client, "sshd", failures(8))
        assert total_alerts(client) == 0

        result = client.post("/api/v1/rules/ssh-brute-force/test").json()
        assert result["enabled"] is False  # a switched-off rule can still be tried
        assert result["events_scanned"] == 8
        assert result["would_raise"] == 1
        assert result["already_raised"] == 0
        (finding,) = result["findings"]
        assert finding["src_ip"] == ATTACKER
        assert finding["event_count"] == 8
        assert total_alerts(client) == 0  # and trying it changed nothing

    def test_a_quiet_rule_reports_nothing(self, client):
        post_log(client, "sshd", failures(2))
        result = client.post("/api/v1/rules/ssh-brute-force/test").json()
        assert (result["would_raise"], result["findings"]) == (0, [])

    def test_empty_database(self, client):
        result = client.post("/api/v1/rules/ssh-brute-force/test").json()
        assert result["events_scanned"] == 0
        assert result["scanned_from"] is None

    def test_unknown_rule(self, client):
        assert client.post("/api/v1/rules/nope/test").status_code == 404

    def test_matches_what_live_detection_raised_for_every_rule(self, client):
        """The dry run and the live engine share one code path; this keeps them from drifting apart."""
        random.seed(7)
        for _name, batch in simulate.build(list(simulate.SCENARIOS), T0, spread_minutes=90):
            post_log(client, batch.log_format, "\n".join(batch.lines), host=simulate.HOST)
        by_rule = alerts_by_rule(client)
        for rule in client.get("/api/v1/rules").json():
            result = client.post(f"/api/v1/rules/{rule['id']}/test").json()
            assert result["would_raise"] == len(by_rule.get(rule["id"], [])), rule["id"]


class Receiver:
    """A real HTTP server on localhost standing in for Slack or any other webhook endpoint."""

    def __init__(self, status: int = 200):
        self.requests: list[dict] = []
        self._arrivals: queue.Queue[None] = queue.Queue()  # one token per request, so none is ever missed
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                receiver.requests.append({"body": body, "headers": {k.lower(): v for k, v in self.headers.items()}})
                self.send_response(status)
                self.end_headers()
                receiver._arrivals.put(None)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/hook/secret-token"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def wait(self, count: int = 1, timeout: float = 5) -> None:
        for _ in range(count):
            try:
                self._arrivals.get(timeout=timeout)
            except queue.Empty:
                pytest.fail("the webhook was not called")

    def stays_quiet(self, seconds: float = 0.5) -> bool:
        try:
            self._arrivals.get(timeout=seconds)
        except queue.Empty:
            return True
        return False

    def close(self):
        self.server.shutdown()


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


def webhook_client(database_url, url, **extra):
    settings = Settings(database_url=database_url, api_key=None, webhook_url=url, _env_file=None, **extra)
    return TestClient(create_app(settings))


class TestWebhook:
    def test_a_critical_alert_is_delivered_with_a_verifiable_signature(self, database_url, receiver):
        with webhook_client(database_url, receiver.url, webhook_secret="s3cret") as client:
            post_log(client, "sshd", BRUTE_FORCE_SUCCESS)
            receiver.wait()
        (request,) = receiver.requests
        payload = json.loads(request["body"])
        assert payload["event"] == "alert.created"
        assert payload["alert"]["rule_id"] == "ssh-brute-force-success"
        assert payload["alert"]["severity"] == "critical"
        assert payload["text"] == payload["content"]  # Slack reads "text", Discord reads "content"
        assert "CRITICAL" in payload["text"]
        expected = hmac.new(b"s3cret", request["body"], hashlib.sha256).hexdigest()
        assert request["headers"]["x-minisiem-signature"] == f"sha256={expected}"

    def test_only_alerts_at_or_above_the_minimum_severity_are_sent(self, database_url, receiver):
        # The same log trips ssh-brute-force (high) and ssh-brute-force-success (critical).
        with webhook_client(database_url, receiver.url) as client:
            post_log(client, "sshd", BRUTE_FORCE_SUCCESS)
            assert {"ssh-brute-force", "ssh-brute-force-success"} <= set(alerts_by_rule(client))
            receiver.wait()
        assert {json.loads(r["body"])["alert"]["severity"] for r in receiver.requests} == {"critical"}

    def test_a_lower_bar_sends_more(self, database_url, receiver):
        with webhook_client(database_url, receiver.url, webhook_min_severity="high") as client:
            post_log(client, "sshd", BRUTE_FORCE_SUCCESS)
            receiver.wait(2)
        rules = {json.loads(r["body"])["alert"]["rule_id"] for r in receiver.requests}
        assert {"ssh-brute-force", "ssh-brute-force-success"} <= rules

    def test_growth_of_an_existing_alert_does_not_notify_again(self, database_url, receiver):
        with webhook_client(database_url, receiver.url) as client:
            post_log(client, "sshd", BRUTE_FORCE_SUCCESS)
            receiver.wait()
            post_log(client, "sshd", failures(3, start=66, every=1))  # more evidence, same attack
            assert receiver.stays_quiet()  # nothing further was sent
        assert len(receiver.requests) == 1

    def test_a_dead_webhook_never_breaks_ingestion(self, database_url):
        with webhook_client(
            database_url, "http://127.0.0.1:9/nothing-listens-here", webhook_timeout_seconds=1
        ) as client:
            result = post_log(client, "sshd", BRUTE_FORCE_SUCCESS)
            assert result["alerts_created"] >= 1
            assert "ssh-brute-force-success" in alerts_by_rule(client)

    def test_status_never_exposes_the_secret_part_of_the_url(self, database_url, receiver):
        with webhook_client(database_url, receiver.url) as client:
            status = client.get("/api/v1/notifications").json()
        assert status == {"enabled": True, "min_severity": "critical", "destination": "127.0.0.1"}
        assert "secret-token" not in json.dumps(status)

    def test_the_test_message_reports_what_the_receiver_said(self, database_url, receiver):
        with webhook_client(database_url, receiver.url) as client:
            assert client.post("/api/v1/notifications/test").json() == {"delivered": True, "status": 200, "error": None}
            receiver.wait()
        assert json.loads(receiver.requests[0]["body"])["event"] == "test"

    def test_the_test_message_surfaces_a_failing_receiver(self, database_url):
        failing = Receiver(status=500)
        try:
            with webhook_client(database_url, failing.url) as client:
                result = client.post("/api/v1/notifications/test").json()
        finally:
            failing.close()
        assert (result["delivered"], result["status"]) == (False, 500)

    def test_unconfigured(self, client):
        assert client.get("/api/v1/notifications").json()["enabled"] is False
        assert client.post("/api/v1/notifications/test").status_code == 409

    def test_a_blank_url_means_off(self, database_url):
        """Docker Compose passes an empty string when the variable is not set."""
        assert Settings(database_url=database_url, webhook_url="", _env_file=None).webhook_url is None

    def test_only_http_urls_are_accepted(self, database_url):
        with pytest.raises(ValueError, match="http"):
            Settings(database_url=database_url, webhook_url="file:///etc/passwd", _env_file=None)


def read_csv(response) -> list[dict]:
    assert response.status_code == 200, response.text
    return list(csv.DictReader(io.StringIO(response.text)))


class TestCsvExport:
    @pytest.fixture
    def loaded(self, client):
        post_log(client, "sshd", BRUTE_FORCE_SUCCESS)
        post_log(client, "firewall", "\n".join(simulate._ufw(T0, "BLOCK", "203.0.113.99", p) for p in range(20, 30)))
        return client

    def test_alerts_export_is_a_download_with_every_matching_row(self, loaded):
        response = loaded.get("/api/v1/alerts/export.csv", params={"sort": "score"})
        assert response.headers["content-type"].startswith("text/csv")
        assert response.headers["content-disposition"].startswith('attachment; filename="alerts-')
        rows = read_csv(response)
        assert len(rows) == total_alerts(loaded) == int(response.headers["x-total-rows"])
        assert [int(r["score"]) for r in rows] == sorted((int(r["score"]) for r in rows), reverse=True)
        assert {"id", "rule_id", "severity", "src_ip", "first_seen", "last_seen"} <= set(rows[0])

    def test_alert_filters_apply_to_the_export(self, loaded):
        rows = read_csv(loaded.get("/api/v1/alerts/export.csv", params={"severity": "critical"}))
        assert rows and {r["severity"] for r in rows} == {"critical"}
        assert read_csv(loaded.get("/api/v1/alerts/export.csv", params={"src_ip": "198.18.0.1"})) == []

    def test_events_export_honours_the_search_filters(self, loaded):
        everything = read_csv(loaded.get("/api/v1/events/export.csv"))
        assert len(everything) == loaded.get("/api/v1/events").json()["total"] == 17
        scanner = read_csv(loaded.get("/api/v1/events/export.csv", params={"src_ip": "203.0.113.99"}))
        assert len(scanner) == 10
        assert {r["dst_port"] for r in scanner} == {str(p) for p in range(20, 30)}
        assert scanner[0]["time"].endswith("Z")

    def test_cells_that_look_like_formulas_are_defused(self, client):
        hostile = '=HYPERLINK("http://evil.example","click")'
        client.post(
            "/api/v1/ingest/events",
            json=[{"source_type": "AUTH", "action": "LOGIN_FAILURE", "src_ip": "203.0.113.5", "username": hostile}],
        )
        (row,) = read_csv(client.get("/api/v1/events/export.csv"))
        assert row["username"] == "'" + hostile
        assert row["src_ip"] == "203.0.113.5"  # ordinary values are untouched

    def test_numbers_are_not_mangled(self, loaded):
        rows = read_csv(loaded.get("/api/v1/events/export.csv", params={"src_ip": "203.0.113.99"}))
        assert all(r["dst_port"].isdigit() for r in rows)
