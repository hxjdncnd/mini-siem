#!/usr/bin/env python3
"""Attack simulator: generates realistic log lines for attack scenarios and sends them to Mini SIEM.

Standard library only, so it runs anywhere Python does:

    python simulator/simulate.py                       # every scenario, against http://localhost:8000
    python simulator/simulate.py -s brute_force port_scan
    python simulator/simulate.py --list
    python simulator/simulate.py --dry-run             # print the log lines instead of sending them

It produces *raw log text* (sshd, nginx, UFW) rather than pre-structured events, so a run exercises
the whole pipeline: parsing, normalization, storage, detection and alerting.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

HOST = "web01"
SERVER_IP = "10.0.0.5"

# Documentation / test address ranges (RFC 5737): safe to use, never real hosts.
OFFICE_IPS = ["198.51.100.7", "198.51.100.23", "198.51.100.41"]
STAFF = ["harshil", "alice", "bob", "deploy"]
BROWSERS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
PAGES = ["/", "/about", "/pricing", "/docs", "/docs/getting-started", "/login", "/static/app.css", "/static/app.js"]


@dataclass
class Batch:
    """Lines of one log format, ready to POST to /api/v1/ingest/<log_format>."""

    log_format: str
    lines: list[str]


# --- log line builders -------------------------------------------------------------------------


def _sshd(ts: datetime, pid: int, message: str) -> str:
    return f"{ts.isoformat(timespec='milliseconds')} {HOST} sshd[{pid}]: {message}"


def _sudo(ts: datetime, user: str, command: str) -> str:
    return (
        f"{ts.isoformat(timespec='milliseconds')} {HOST} sudo:  {user} : TTY=pts/0 ; "
        f"PWD=/home/{user} ; USER=root ; COMMAND={command}"
    )


def _nginx(ts: datetime, ip: str, method: str, path: str, status: int, agent: str, user: str = "-") -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - {user} [{stamp}] "{method} {path} HTTP/1.1" {status} {random.randint(120, 9000)} "-" "{agent}"'


def _ufw(ts: datetime, verdict: str, src: str, dst_port: int, proto: str = "TCP") -> str:
    return (
        f"{ts.isoformat(timespec='milliseconds')} {HOST} kernel: [UFW {verdict}] IN=eth0 OUT= "
        f"MAC=02:42:ac:11:00:02:02:42:ac:11:00:01:08:00 SRC={src} DST={SERVER_IP} LEN=44 TTL=242 "
        f"PROTO={proto} SPT={random.randint(1024, 65000)} DPT={dst_port} WINDOW=1024 SYN URGP=0"
    )


def _failed(ts: datetime, user: str, ip: str, known: bool = True) -> str:
    who = user if known else f"invalid user {user}"
    return _sshd(
        ts, random.randint(1000, 9999), f"Failed password for {who} from {ip} port {random.randint(30000, 65000)} ssh2"
    )


def _accepted(ts: datetime, user: str, ip: str, method: str = "publickey") -> str:
    return _sshd(
        ts,
        random.randint(1000, 9999),
        f"Accepted {method} for {user} from {ip} port {random.randint(30000, 65000)} ssh2",
    )


# --- scenarios ---------------------------------------------------------------------------------
# Each takes the moment the scenario starts and returns the batches to send.


def normal(start: datetime) -> list[Batch]:
    """Ordinary background activity: page views, staff logins, a mistyped password. Should raise nothing."""
    web, auth, fw = [], [], []
    for i in range(120):
        ts = start + timedelta(seconds=i * 12 + random.random() * 5)
        web.append(_nginx(ts, random.choice(OFFICE_IPS), "GET", random.choice(PAGES), 200, random.choice(BROWSERS)))
        if i % 15 == 0:
            fw.append(_ufw(ts, "ALLOW", random.choice(OFFICE_IPS), 443))
    for i, user in enumerate(STAFF):
        ts = start + timedelta(minutes=2 + i * 5)
        ip = OFFICE_IPS[i % len(OFFICE_IPS)]
        if user == "bob":
            auth.append(_failed(ts - timedelta(seconds=8), user, ip))
        auth.append(_accepted(ts, user, ip))
        auth.append(
            _sshd(
                ts + timedelta(seconds=1),
                4242,
                f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
            )
        )
    auth.append(_sudo(start + timedelta(minutes=4), "harshil", "/usr/bin/systemctl restart nginx"))
    return [Batch("nginx", web), Batch("sshd", auth), Batch("firewall", fw)]


def brute_force(start: datetime) -> list[Batch]:
    """One address hammering the root account with wrong passwords."""
    ip = "203.0.113.50"
    return [Batch("sshd", [_failed(start + timedelta(seconds=i * 1.5), "root", ip) for i in range(40)])]


def brute_force_success(start: datetime) -> list[Batch]:
    """Wrong passwords for 'deploy' until one works: the brute force succeeded."""
    ip = "203.0.113.61"
    lines = [_failed(start + timedelta(seconds=i * 3), "deploy", ip) for i in range(9)]
    lines.append(_accepted(start + timedelta(seconds=30), "deploy", ip, method="password"))
    return [Batch("sshd", lines)]


def password_spray(start: datetime) -> list[Batch]:
    """One guess each against many accounts, slow enough to dodge per-account lockouts."""
    ip = "203.0.113.72"
    names = [
        "admin",
        "test",
        "oracle",
        "postgres",
        "ubuntu",
        "git",
        "jenkins",
        "ftpuser",
        "guest",
        "backup",
        "pi",
        "support",
    ]
    lines = []
    for i, name in enumerate(names):
        ts = start + timedelta(seconds=i * 14)
        lines.append(_sshd(ts, 5000 + i, f"Invalid user {name} from {ip} port {40000 + i}"))
        lines.append(_failed(ts + timedelta(seconds=2), name, ip, known=False))
    return [Batch("sshd", lines)]


def port_scan(start: datetime) -> list[Batch]:
    """A fast sweep across common service ports, all dropped by the firewall."""
    ip = "203.0.113.99"
    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        445,
        993,
        995,
        1433,
        1521,
        2049,
        3306,
        3389,
        5432,
        5900,
        5985,
        6379,
        8000,
        8080,
        8443,
        8888,
        9200,
        11211,
        27017,
    ]
    return [
        Batch("firewall", [_ufw(start + timedelta(milliseconds=i * 150), "BLOCK", ip, p) for i, p in enumerate(ports)])
    ]


def web_scan(start: datetime) -> list[Batch]:
    """Directory brute forcing: a wordlist of paths, nearly all 404."""
    ip = "203.0.113.77"
    words = [
        "admin",
        "backup",
        "wp-login.php",
        "phpmyadmin",
        "config",
        "old",
        "test",
        "dev",
        "api/v2",
        "console",
        "server-status",
        "manager",
        "uploads",
        "private",
        "db",
        "staging",
        "portal",
        "shell",
        "cgi-bin",
        "tmp",
    ]
    lines = [
        _nginx(
            start + timedelta(milliseconds=i * 400), ip, "GET", f"/{word}", 403 if i % 9 == 0 else 404, "gobuster/3.6"
        )
        for i, word in enumerate(words * 2)
    ]
    return [Batch("nginx", lines)]


def sql_injection(start: datetime) -> list[Batch]:
    """sqlmap probing a search parameter."""
    ip = "203.0.113.88"
    payloads = [
        "1%27%20OR%20%271%27=%271",
        "1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "1%27%20AND%20SLEEP(5)--",
        "1;%20DROP%20TABLE%20users--",
        "1%20UNION%20ALL%20SELECT%20NULL,table_name%20FROM%20information_schema.tables--",
        "1+or+1=1",
    ]
    lines = [
        _nginx(
            start + timedelta(seconds=i * 2), ip, "GET", f"/search?q={p}", 500 if i % 2 else 200, "sqlmap/1.8.4#stable"
        )
        for i, p in enumerate(payloads)
    ]
    return [Batch("nginx", lines)]


def path_traversal(start: datetime) -> list[Batch]:
    """Hunting for files a web server should never hand out."""
    ip = "203.0.113.93"
    paths = [
        "/download?file=../../../../etc/passwd",
        "/.env",
        "/.git/config",
        "/static/..%2f..%2f..%2fetc/passwd",
        "/.aws/credentials",
    ]
    lines = [_nginx(start + timedelta(seconds=i * 4), ip, "GET", p, 404, BROWSERS[2]) for i, p in enumerate(paths)]
    return [Batch("nginx", lines)]


def sudo_abuse(start: datetime) -> list[Batch]:
    """A logged-in account reading password hashes and creating itself a backdoor user."""
    ip = OFFICE_IPS[1]
    lines = [
        _accepted(start, "bob", ip),
        _sudo(start + timedelta(seconds=40), "bob", "/usr/bin/cat /etc/shadow"),
        _sudo(start + timedelta(seconds=75), "bob", "/usr/sbin/useradd -m -G sudo svc_backup"),
        _sudo(start + timedelta(seconds=110), "bob", "/usr/bin/chmod u+s /usr/bin/find"),
    ]
    return [Batch("sshd", lines)]


def account_takeover(start: datetime) -> list[Batch]:
    """One account logging in from four unrelated addresses inside half an hour."""
    ips = [OFFICE_IPS[0], "203.0.113.120", "192.0.2.45", "192.0.2.201"]
    return [
        Batch(
            "sshd",
            [_accepted(start + timedelta(minutes=i * 7), "alice", ip, method="password") for i, ip in enumerate(ips)],
        )
    ]


def root_login(start: datetime) -> list[Batch]:
    """Someone logging in directly as root."""
    return [Batch("sshd", [_accepted(start, "root", "192.0.2.77", method="password")])]


SCENARIOS = {
    f.__name__: f
    for f in (
        normal,
        brute_force,
        brute_force_success,
        password_spray,
        port_scan,
        web_scan,
        sql_injection,
        path_traversal,
        sudo_abuse,
        account_takeover,
        root_login,
    )
}

# Which detection rules each scenario is expected to trip (also asserted by the test suite).
EXPECTED_ALERTS = {
    "normal": set(),
    "brute_force": {"ssh-brute-force"},
    "brute_force_success": {"ssh-brute-force", "ssh-brute-force-success"},
    "password_spray": {"password-spray", "ssh-brute-force"},
    "port_scan": {"port-scan"},
    "web_scan": {"web-content-discovery", "web-scanner-user-agent"},
    "sql_injection": {"web-sql-injection", "web-scanner-user-agent"},
    "path_traversal": {"web-path-traversal"},
    "sudo_abuse": {"sudo-sensitive-command"},
    "account_takeover": {"login-from-many-addresses"},
    "root_login": {"root-ssh-login"},
}


def build(names: list[str], end: datetime, spread_minutes: int) -> list[tuple[str, Batch]]:
    """Lay the scenarios out across the `spread_minutes` before `end`, so a dashboard timeline has shape."""
    window_start = end - timedelta(minutes=spread_minutes)
    out = []
    for i, name in enumerate(names):
        if name == "normal":
            start = window_start  # background noise runs the whole time
        else:
            # Leave the last 30 minutes free so no scenario runs past `end`.
            usable = max(1, spread_minutes - 30)
            start = window_start + timedelta(minutes=usable * (i + 1) / (len(names) + 1))
        out += [(name, batch) for batch in SCENARIOS[name](start)]
    return out


def send(url: str, batch: Batch, api_key: str | None) -> dict:
    query = urllib.parse.urlencode({"host": HOST})
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/v1/ingest/{batch.log_format}?{query}",
        data="\n".join(batch.lines).encode(),
        headers={"Content-Type": "text/plain", **({"X-API-Key": api_key} if api_key else {})},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("-u", "--url", default="http://localhost:8000", help="Mini SIEM base URL")
    parser.add_argument(
        "-s", "--scenario", nargs="+", default=["all"], metavar="NAME", help="scenarios to run (default: all)"
    )
    parser.add_argument("--api-key", help="value for the X-API-Key header, if the server requires one")
    parser.add_argument(
        "--spread-minutes",
        type=int,
        default=90,
        help="spread the scenarios across this many minutes ending now (default: 90)",
    )
    parser.add_argument("--seed", type=int, help="make the random details repeatable")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--dry-run", action="store_true", help="print the log lines instead of sending them")
    args = parser.parse_args(argv)

    if args.list:
        for name, scenario in SCENARIOS.items():
            print(f"{name:22} {scenario.__doc__}")
        return 0

    names = list(SCENARIOS) if "all" in args.scenario else args.scenario
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s) {unknown}; use --list to see them")
    if args.seed is not None:
        random.seed(args.seed)

    plan = build(names, datetime.now(timezone.utc), args.spread_minutes)
    if args.dry_run:
        for name, batch in plan:
            print(f"# {name} -> {batch.log_format}")
            print("\n".join(batch.lines))
        return 0

    totals = {"stored": 0, "alerts_created": 0}
    for name, batch in plan:
        try:
            result = send(args.url, batch, args.api_key)
        except urllib.error.HTTPError as e:
            print(f"{name}: server answered {e.code}: {e.read().decode(errors='replace')[:300]}", file=sys.stderr)
            return 1
        except urllib.error.URLError as e:
            print(f"Could not reach {args.url}: {e.reason}. Is the backend running?", file=sys.stderr)
            return 1
        for key in totals:
            totals[key] += result[key]
        print(
            f"{name:22} {batch.log_format:9} {result['stored']:4} events stored, "
            f"{result['alerts_created']} new alerts, {result['alerts_updated']} updated"
            + (f", {result['failed']} lines FAILED to parse" if result["failed"] else "")
        )
    print(f"\nDone: {totals['stored']} events, {totals['alerts_created']} alerts raised.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
