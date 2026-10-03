"""Hermetic tests for port_watch."""

from aegis.engines.base import ScanContext
from aegis.engines.port_watch import PortWatch


def make_ctx(port_scan, expected_ports):
    return ScanContext(data={"port_scan": port_scan, "expected_ports": expected_ports})


def test_unexpected_rdp_scores_80():
    ctx = make_ctx({"web1": [80, 443, 3389]}, {"web1": [80, 443]})
    findings = PortWatch().scan(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.score == 80
    assert f.severity == "high"
    assert f.entities["port"] == 3389
    assert f.entities["host"] == "web1"


def test_unexpected_smb_scores_85():
    ctx = make_ctx({"db1": [445]}, {"db1": []})
    assert PortWatch().scan(ctx)[0].score == 85


def test_unknown_port_uses_default_risk_40():
    ctx = make_ctx({"web1": [8080]}, {"web1": [80]})
    findings = PortWatch().scan(ctx)
    unexpected = [f for f in findings if f.entities["port"] == 8080]
    assert len(unexpected) == 1
    assert unexpected[0].score == 40
    assert unexpected[0].evidence["port_risk"] == 40


def test_expected_but_closed_is_informational_10():
    ctx = make_ctx({"web1": [80]}, {"web1": [80, 443]})
    findings = PortWatch().scan(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.score == 10
    assert f.severity == "low"
    assert "down" in f.title.lower()
    assert "availability" in f.tags


def test_all_expected_open_no_findings():
    ctx = make_ctx({"web1": [80, 443]}, {"web1": [80, 443]})
    assert PortWatch().scan(ctx) == []


def test_host_only_in_expected_reports_all_closed():
    ctx = make_ctx({}, {"web1": [443]})
    findings = PortWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 10


def test_evidence_includes_added_removed_context():
    ctx = make_ctx({"web1": [22]}, {"web1": [80]})
    findings = PortWatch().scan(ctx)
    unexpected = [f for f in findings if f.entities["port"] == 22][0]
    closed = [f for f in findings if f.entities["port"] == 80][0]
    assert unexpected.evidence["open_ports"] == [22]
    assert closed.evidence["expected_ports"] == [80]


def test_multiple_hosts():
    ctx = make_ctx(
        {"a": [3389], "b": [80]},
        {"a": [80], "b": [80]},
    )
    findings = PortWatch().scan(ctx)
    assert len(findings) == 2  # a: 3389 unexpected + 80 closed; b: clean
