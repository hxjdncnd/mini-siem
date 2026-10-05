from tests.conftest import alerts_by_rule, post_log, sample


def test_health(client):
    assert client.get("/health").json() == {"status": "ok", "rules": 11}


def test_ingest_sample_auth_log_and_search(client):
    result = post_log(client, "sshd", sample("auth.log"))
    assert (result["received"], result["stored"], result["skipped"], result["failed"]) == (10, 9, 1, 0)

    page = client.get("/api/v1/events", params={"action": "LOGIN_FAILURE", "src_ip": "203.0.113.50"}).json()
    assert page["total"] == 5
    assert {e["host"] for e in page["items"]} == {"web01"}
    times = [e["timestamp"] for e in page["items"]]
    assert times == sorted(times, reverse=True)


def test_all_three_sample_formats(client):
    assert post_log(client, "sshd", sample("auth.log"))["stored"] == 9
    assert post_log(client, "nginx", sample("access.log"), host="web01")["stored"] == 7
    assert post_log(client, "firewall", sample("ufw.log"))["stored"] == 5

    def total(**params):
        return client.get("/api/v1/events", params=params).json()["total"]

    assert total() == 21
    assert total(source_type="WEB", host="web01") == 7  # access logs take the host from ?host=
    assert total(source_type="FIREWALL", action="CONN_BLOCKED") == 4
    assert total(q="sqlmap") == 1
    assert total(q="100%_literal") == 0  # LIKE wildcards in the search text are escaped


def test_bad_lines_are_reported_but_do_not_reject_the_batch(client):
    body = "\n".join(
        [
            "Oct  5 14:02:13 web01 sshd[814]: Failed password for root from 203.0.113.50 port 51140 ssh2",
            "complete garbage",
            "",
            "Oct  5 14:02:15 web01 sshd[816]: Failed password for root from 203.0.113.50 port 51158 ssh2",
        ]
    )
    result = post_log(client, "sshd", body)
    assert (result["received"], result["stored"], result["failed"]) == (3, 2, 1)
    assert result["errors"] == [{"line": 2, "reason": "Not a syslog line"}]


def test_time_range_and_paging(client):
    post_log(client, "nginx", sample("access.log"))
    page = client.get("/api/v1/events", params={"from": "2026-10-05T14:11:00Z", "to": "2026-10-05T14:12:00Z"}).json()
    assert page["total"] == 4

    page = client.get("/api/v1/events", params={"size": 3, "page": 2}).json()
    assert (page["total"], len(page["items"]), page["page"], page["size"]) == (7, 1, 2, 3)


def test_structured_events_and_fetch_by_id(client):
    response = client.post(
        "/api/v1/ingest/events",
        json=[
            {
                "timestamp": "2026-10-05T10:00:00-04:00",
                "source_type": "AUTH",
                "action": "LOGIN_FAILURE",
                "host": "db01",
                "src_ip": "203.0.113.9",
                "username": "postgres",
            }
        ],
    )
    assert response.status_code == 200 and response.json()["stored"] == 1

    event = client.get("/api/v1/events", params={"host": "db01"}).json()["items"][0]
    fetched = client.get(f"/api/v1/events/{event['id']}").json()
    assert fetched["username"] == "postgres"
    assert fetched["timestamp"] == "2026-10-05T14:00:00Z"


def test_bad_requests(client):
    def post_events(payload):
        return client.post("/api/v1/ingest/events", json=payload).status_code

    assert client.post("/api/v1/ingest/cobol", content="x").status_code == 400
    assert post_events([]) == 422
    assert post_events([{"source_type": "AUTH"}]) == 422
    assert post_events([{"source_type": "AUTH", "action": "LOGIN_FAILURE", "src_port": 70000}]) == 422
    assert client.get("/api/v1/events", params={"size": 0}).status_code == 422
    assert client.get("/api/v1/events", params={"action": "NOT_A_THING"}).status_code == 422
    assert client.get("/api/v1/events/does-not-exist").status_code == 404
    assert client.get("/api/v1/alerts/does-not-exist").status_code == 404


def test_request_size_limit(settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    settings.max_lines_per_request = 3
    with TestClient(create_app(settings)) as client:
        response = client.post("/api/v1/ingest/sshd", content="x\n" * 4)
        assert response.status_code == 400
        assert "Too many lines" in response.json()["detail"]


def test_api_key_is_enforced_when_configured(settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    settings.api_key = "s3cret"
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").status_code == 200  # health stays open for container probes
        assert client.get("/api/v1/events").status_code == 401
        assert client.get("/api/v1/events", headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get("/api/v1/events", headers={"X-API-Key": "s3cret"}).status_code == 200


def test_alert_triage_flow(client):
    post_log(client, "sshd", sample("auth.log"))
    alert = alerts_by_rule(client)["ssh-brute-force"][0]
    assert alert["status"] == "OPEN"

    detail = client.get(f"/api/v1/alerts/{alert['id']}").json()
    assert detail["event_count"] == len(detail["events"]) == 5
    assert all(e["action"] == "LOGIN_FAILURE" and e["src_ip"] == "203.0.113.50" for e in detail["events"])

    updated = client.patch(
        f"/api/v1/alerts/{alert['id']}", json={"status": "ACKNOWLEDGED", "note": "Blocking at the firewall"}
    ).json()
    assert (updated["status"], updated["note"]) == ("ACKNOWLEDGED", "Blocking at the firewall")
    assert client.patch(f"/api/v1/alerts/{alert['id']}", json={}).status_code == 400
    assert client.patch(f"/api/v1/alerts/{alert['id']}", json={"status": "DELETED"}).status_code == 422

    def count(**params):
        return client.get("/api/v1/alerts", params=params).json()["total"]

    assert count(status="ACKNOWLEDGED") == 1
    assert count(active="true") == count()
    client.patch(f"/api/v1/alerts/{alert['id']}", json={"status": "RESOLVED"})
    assert count(active="true") == count() - 1
    assert count(active="false") == 1


def test_alert_filters_and_sorting(client):
    post_log(client, "sshd", sample("auth.log"))
    post_log(client, "nginx", sample("access.log"))

    def alerts(**params):
        return client.get("/api/v1/alerts", params=params).json()["items"]

    assert {a["rule_id"] for a in alerts(severity="critical")} == {"ssh-brute-force-success"}
    assert all(a["severity"] in ("high", "critical") for a in alerts(min_severity="high"))
    assert {a["src_ip"] for a in alerts(src_ip="203.0.113.77")} == {"203.0.113.77"}
    assert alerts(rule_id="no-such-rule") == []
    scores = [a["score"] for a in alerts(sort="score")]
    assert scores == sorted(scores, reverse=True) and scores[0] >= 90


def test_rules_endpoint_reports_alert_counts(client):
    post_log(client, "sshd", sample("auth.log"))
    rules = {r["id"]: r for r in client.get("/api/v1/rules").json()}
    assert len(rules) == 11
    assert rules["ssh-brute-force"]["alert_count"] == 1
    assert rules["port-scan"]["alert_count"] == 0
    assert rules["ssh-brute-force"]["threshold"] == 5


def test_stats_summary(client):
    post_log(client, "sshd", sample("auth.log"))
    post_log(client, "nginx", sample("access.log"))
    post_log(client, "firewall", sample("ufw.log"))

    stats = client.get(
        "/api/v1/stats/summary",
        params={
            "from": "2026-10-05T14:00:00Z",
            "to": "2026-10-05T14:30:00Z",
            "bucket_seconds": 600,
            "top": 2,
        },
    ).json()
    assert stats["total_events"] == 21
    assert {c["key"]: c["count"] for c in stats["events_by_source"]} == {"AUTH": 9, "WEB": 7, "FIREWALL": 5}
    assert stats["top_source_ips"][0] == {"key": "203.0.113.50", "count": 7}
    assert len(stats["top_source_ips"]) == 2
    assert [b["count"] for b in stats["events_over_time"]] == [9, 7, 5]
    assert stats["events_over_time"][1]["start"] == "2026-10-05T14:10:00Z"
    assert stats["total_alerts"] == stats["open_alerts"] == sum(c["count"] for c in stats["alerts_by_rule"])
    assert stats["total_alerts"] >= 5

    empty = client.get(
        "/api/v1/stats/summary", params={"from": "2020-01-01T00:00:00Z", "to": "2020-01-02T00:00:00Z"}
    ).json()
    assert (empty["total_events"], empty["total_alerts"]) == (0, 0)
    assert len(empty["events_over_time"]) <= 60

    assert (
        client.get(
            "/api/v1/stats/summary", params={"from": "2026-01-02T00:00:00Z", "to": "2026-01-01T00:00:00Z"}
        ).status_code
        == 400
    )
    assert client.get("/api/v1/stats/summary", params={"bucket_seconds": 1}).status_code == 400
