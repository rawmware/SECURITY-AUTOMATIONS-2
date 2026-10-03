"""Hermetic tests for auth_watch."""

from datetime import datetime, timedelta, timezone

from aegis.engines.auth_watch import AuthWatch
from aegis.engines.base import ScanContext

BASE = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)


def line(minutes, ip, user, result):
    return f"{(BASE + timedelta(minutes=minutes)).isoformat()} {ip} {user} {result}"


def make_ctx(lines, options=None):
    return ScanContext(options=options or {}, data={"auth_log": lines})


def test_brute_force_triggers():
    lines = [line(m, "203.0.113.5", "alice", "fail") for m in range(8)]
    findings = AuthWatch().scan(make_ctx(lines))
    assert len(findings) == 1
    f = findings[0]
    assert f.score == 85
    assert f.severity == "high"
    assert f.entities["ip"] == "203.0.113.5"
    assert "brute-force" in f.tags


def test_fails_spread_beyond_window_no_brute_force():
    # 8 fails, but spread 20 minutes apart: never 8 inside 10 minutes
    lines = [line(m * 20, "203.0.113.5", "alice", "fail") for m in range(8)]
    findings = AuthWatch().scan(make_ctx(lines))
    assert not [f for f in findings if "brute-force" in f.tags]


def test_below_threshold_no_brute_force():
    lines = [line(m, "203.0.113.5", "alice", "fail") for m in range(7)]
    assert AuthWatch().scan(make_ctx(lines)) == []


def test_option_override_fail_threshold():
    lines = [line(m, "203.0.113.5", "alice", "fail") for m in range(3)]
    ctx = make_ctx(lines, options={"fail_threshold": 3})
    findings = AuthWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].entities["ip"] == "203.0.113.5"


def test_password_spray_triggers():
    users = ["alice", "bob", "carol", "dave", "erin"]
    lines = [line(m, "203.0.113.6", u, "fail") for m, u in enumerate(users)]
    findings = AuthWatch().scan(make_ctx(lines))
    spray = [f for f in findings if "password-spray" in f.tags]
    assert len(spray) == 1
    assert spray[0].score == 85
    assert spray[0].evidence["user_count"] == 5


def test_distributed_attack_triggers():
    ips = [f"198.51.100.{i}" for i in range(1, 6)]
    lines = [line(m, ip, "frank", "fail") for m, ip in enumerate(ips)]
    findings = AuthWatch().scan(make_ctx(lines))
    dist = [f for f in findings if "distributed-attack" in f.tags]
    assert len(dist) == 1
    assert dist[0].score == 60
    assert dist[0].entities["user"] == "frank"


def test_clean_log_no_findings():
    lines = [line(m, "203.0.113.7", "alice", "ok") for m in range(10)]
    assert AuthWatch().scan(make_ctx(lines)) == []


def test_malformed_lines_skipped():
    lines = [
        "not a log line",
        "2026-10-03T12:00:00+00:00 203.0.113.5",  # too short
        "garbage-time 203.0.113.5 alice fail",  # bad timestamp
        line(0, "203.0.113.5", "alice", "ok"),
    ]
    assert AuthWatch().scan(make_ctx(lines)) == []


def test_successes_do_not_count_as_fails():
    lines = [line(m, "203.0.113.5", "alice", "ok") for m in range(8)]
    lines += [line(m + 8, "203.0.113.5", "alice", "fail") for m in range(7)]
    assert AuthWatch().scan(make_ctx(lines)) == []
