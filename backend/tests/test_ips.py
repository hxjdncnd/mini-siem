import ipaddress

import pytest

from app.api.entities import classify
from tests.conftest import post_log, sample


@pytest.mark.parametrize(
    ("address", "kind", "internal"),
    [
        ("203.0.113.50", "documentation", False),
        ("198.51.100.7", "documentation", False),
        ("2001:db8::1", "documentation", False),
        ("10.0.0.5", "private", True),
        ("192.168.1.20", "private", True),
        ("127.0.0.1", "loopback", True),
        ("169.254.10.1", "link_local", True),
        ("224.0.0.1", "multicast", False),
        ("0.0.0.0", "reserved", False),
        ("8.8.8.8", "public", False),
    ],
)
def test_classification(address, kind, internal):
    result = classify(ipaddress.ip_address(address))
    assert (result.kind, result.internal) == (kind, internal)


def test_profile_matches_what_the_event_and_alert_apis_say(client):
    post_log(client, "sshd", sample("auth.log"))
    profile = client.get("/api/v1/ips/203.0.113.50").json()

    events = client.get("/api/v1/events", params={"src_ip": "203.0.113.50", "size": 500}).json()
    alerts = client.get("/api/v1/alerts", params={"src_ip": "203.0.113.50", "size": 500}).json()

    assert profile["ip"] == "203.0.113.50"
    assert profile["classification"]["kind"] == "documentation"
    assert profile["event_count"] == events["total"] == 7
    assert sum(b["count"] for b in profile["events_over_time"]) == profile["event_count"]
    assert sum(c["count"] for c in profile["actions"]) == profile["event_count"]
    assert {a["id"] for a in profile["alerts"]} == {a["id"] for a in alerts["items"]}
    assert profile["max_score"] == max(a["score"] for a in alerts["items"])
    assert profile["first_seen"] < profile["last_seen"]
    assert {u["key"] for u in profile["usernames"]} == {"admin", "root"}
    assert profile["hosts"] == [{"key": "web01", "count": 7}]
    assert len(profile["recent_events"]) == 7
    times = [e["timestamp"] for e in profile["recent_events"]]
    assert times == sorted(times, reverse=True)


def test_profile_collects_web_paths_and_firewall_ports(client):
    post_log(client, "nginx", sample("access.log"), host="web01")
    post_log(client, "firewall", sample("ufw.log"))
    web = client.get("/api/v1/ips/203.0.113.77").json()
    assert web["http_paths"], "a scanning address should list the paths it requested"
    scanner = client.get("/api/v1/ips/203.0.113.99").json()
    assert {p["key"] for p in scanner["dst_ports"]} == {"21", "23", "3306", "5432"}


def test_ipv6_is_matched_by_canonical_spelling(client):
    client.post(
        "/api/v1/ingest/events",
        json=[{"source_type": "AUTH", "action": "LOGIN_FAILURE", "src_ip": "2001:db8::1", "username": "root"}],
    ).raise_for_status()
    assert client.get("/api/v1/ips/2001:0db8:0:0:0:0:0:1").json()["event_count"] == 1


def test_unknown_address_is_404_and_garbage_is_400(client):
    assert client.get("/api/v1/ips/203.0.113.250").status_code == 404
    response = client.get("/api/v1/ips/not-an-ip")
    assert response.status_code == 400
    assert "not a valid IP" in response.json()["detail"]


def test_single_event_profile_has_one_bucket(client):
    post_log(
        client, "sshd", "Oct  5 14:02:13 web01 sshd[814]: Failed password for root from 203.0.113.50 port 51140 ssh2"
    )
    profile = client.get("/api/v1/ips/203.0.113.50").json()
    assert profile["event_count"] == 1
    assert [b["count"] for b in profile["events_over_time"]] == [1]
