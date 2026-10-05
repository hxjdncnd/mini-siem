from datetime import UTC, datetime

import pytest

from app.enums import EventAction, SourceType
from app.parsers import MalformedLine, ParseContext
from app.parsers.firewall import FirewallParser
from app.parsers.nginx import NginxAccessParser
from app.parsers.sshd import SshdAuthParser

sshd = SshdAuthParser()
nginx = NginxAccessParser()
firewall = FirewallParser()


class TestSshd:
    def test_failed_password(self, ctx):
        e = sshd.parse(
            "Oct  5 14:02:13 web01 sshd[814]: Failed password for root from 203.0.113.50 port 51140 ssh2", ctx
        )
        assert e.source_type == SourceType.AUTH
        assert e.action == EventAction.LOGIN_FAILURE
        assert e.timestamp == datetime(2026, 10, 5, 14, 2, 13, tzinfo=UTC)
        assert (e.host, e.username, e.src_ip, e.src_port) == ("web01", "root", "203.0.113.50", 51140)

    def test_failed_password_for_invalid_user_keeps_the_real_username(self, ctx):
        e = sshd.parse(
            "Oct  5 14:02:11 web01 sshd[812]: Failed password for invalid user admin from 203.0.113.50 port 51122 ssh2",
            ctx,
        )
        assert e.action == EventAction.LOGIN_FAILURE
        assert e.username == "admin"

    def test_accepted_publickey(self, ctx):
        e = sshd.parse(
            "Oct  5 14:05:40 web01 sshd[901]: Accepted publickey for harshil from 198.51.100.7 port 60022 ssh2: ED25519 SHA256:abc",
            ctx,
        )
        assert e.action == EventAction.LOGIN_SUCCESS
        assert (e.username, e.src_ip) == ("harshil", "198.51.100.7")

    def test_invalid_user_without_port(self, ctx):
        e = sshd.parse("Oct  5 14:02:09 web01 sshd[812]: Invalid user oracle from 203.0.113.50", ctx)
        assert e.action == EventAction.INVALID_USER
        assert (e.username, e.src_port) == ("oracle", None)

    def test_sudo_command(self, ctx):
        e = sshd.parse(
            "Oct  5 14:06:02 web01 sudo:  harshil : TTY=pts/0 ; PWD=/home/harshil ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
            ctx,
        )
        assert e.action == EventAction.SUDO_COMMAND
        assert e.username == "harshil"
        assert "COMMAND=/usr/bin/systemctl restart nginx" in e.raw

    def test_iso_timestamp_with_offset(self, ctx):
        e = sshd.parse(
            "2026-10-05T10:02:13.123456-04:00 web01 sshd[814]: Failed password for root from 203.0.113.50 port 51140 ssh2",
            ctx,
        )
        assert e.timestamp == datetime(2026, 10, 5, 14, 2, 13, 123456, tzinfo=UTC)

    def test_december_line_read_in_january_belongs_to_last_year(self):
        january = ParseContext(now=datetime(2027, 1, 2, tzinfo=UTC), default_tz=UTC)
        e = sshd.parse("Dec 31 23:59:00 web01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2", january)
        assert e.timestamp == datetime(2026, 12, 31, 23, 59, tzinfo=UTC)

    def test_default_timezone_applies_to_classic_timestamps(self):
        from zoneinfo import ZoneInfo

        detroit = ParseContext(now=datetime(2026, 10, 6, tzinfo=UTC), default_tz=ZoneInfo("America/Detroit"))
        e = sshd.parse(
            "Oct  5 10:02:13 web01 sshd[814]: Failed password for root from 203.0.113.50 port 51140 ssh2", detroit
        )
        assert e.timestamp == datetime(2026, 10, 5, 14, 2, 13, tzinfo=UTC)

    @pytest.mark.parametrize(
        "line",
        [
            "Oct  5 14:05:41 web01 sshd[901]: pam_unix(sshd:session): session opened for user harshil",
            "Oct  5 14:05:41 web01 cron[77]: (root) CMD (run-parts /etc/cron.hourly)",
            "Oct  5 14:05:41 web01 sudo: pam_unix(sudo:session): session closed for user root",
        ],
    )
    def test_uninteresting_lines_are_skipped_not_errors(self, ctx, line):
        assert sshd.parse(line, ctx) is None

    @pytest.mark.parametrize(
        "line",
        [
            "this is not a log line",
            "Oct 32 14:05:41 web01 sshd[901]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "2026-13-45Tnope web01 sshd[901]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ],
    )
    def test_garbage_is_rejected(self, ctx, line):
        with pytest.raises(MalformedLine):
            sshd.parse(line, ctx)


class TestNginx:
    def test_combined_format(self, ctx):
        e = nginx.parse(
            '203.0.113.77 - - [05/Oct/2026:10:11:16 -0400] "GET /search?q=1%27 HTTP/1.1" 500 0 "-" "sqlmap/1.8"', ctx
        )
        assert e.source_type == SourceType.WEB
        assert e.action == EventAction.HTTP_REQUEST
        assert e.timestamp == datetime(2026, 10, 5, 14, 11, 16, tzinfo=UTC)
        assert (e.src_ip, e.username) == ("203.0.113.77", None)
        assert (e.http_method, e.http_path, e.http_status) == ("GET", "/search?q=1%27", 500)
        assert e.user_agent == "sqlmap/1.8"

    def test_keeps_authenticated_user(self, ctx):
        e = nginx.parse(
            '198.51.100.7 - alice [05/Oct/2026:14:12:40 +0000] "POST /api/login HTTP/1.1" 200 96 "-" "curl/8"', ctx
        )
        assert e.username == "alice"

    def test_common_format_without_referer_and_agent(self, ctx):
        e = nginx.parse('198.51.100.7 - - [05/Oct/2026:14:12:40 +0000] "GET / HTTP/1.1" 200 -', ctx)
        assert (e.http_status, e.user_agent) == (200, None)

    @pytest.mark.parametrize("line", ["nope", '1.2.3.4 - - [not a date] "GET / HTTP/1.1" 200 1 "-" "x"'])
    def test_garbage_is_rejected(self, ctx, line):
        with pytest.raises(MalformedLine):
            nginx.parse(line, ctx)


class TestFirewall:
    def test_blocked_connection(self, ctx):
        e = firewall.parse(
            "Oct  5 14:20:01 web01 kernel: [18234.112233] [UFW BLOCK] IN=eth0 OUT= MAC=02:42 SRC=203.0.113.99 DST=10.0.0.5 LEN=44 PROTO=TCP SPT=44321 DPT=3306 WINDOW=1024 SYN URGP=0",
            ctx,
        )
        assert e.source_type == SourceType.FIREWALL
        assert e.action == EventAction.CONN_BLOCKED
        assert (e.host, e.src_ip, e.dst_ip) == ("web01", "203.0.113.99", "10.0.0.5")
        assert (e.src_port, e.dst_port, e.protocol) == (44321, 3306, "tcp")

    def test_allowed_connection(self, ctx):
        e = firewall.parse(
            "Oct  5 14:21:10 web01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.5 PROTO=TCP SPT=60100 DPT=443",
            ctx,
        )
        assert e.action == EventAction.CONN_ALLOWED

    def test_icmp_has_no_ports(self, ctx):
        e = firewall.parse(
            "Oct  5 14:21:10 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.99 DST=10.0.0.5 PROTO=ICMP TYPE=8 CODE=0",
            ctx,
        )
        assert (e.protocol, e.src_port, e.dst_port) == ("icmp", None, None)

    def test_other_kernel_lines_are_skipped(self, ctx):
        assert firewall.parse("Oct  5 14:21:10 web01 kernel: [18303.5] eth0: link up", ctx) is None

    @pytest.mark.parametrize(
        "line",
        [
            "Oct  5 14:21:10 web01 kernel: [UFW BLOCK] IN=eth0 OUT= PROTO=TCP",
            "Oct  5 14:21:10 web01 kernel: [UFW BLOCK] SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1 DPT=99999",
        ],
    )
    def test_broken_firewall_lines_are_rejected(self, ctx, line):
        with pytest.raises(MalformedLine):
            firewall.parse(line, ctx)
