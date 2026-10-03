"""Hermetic tests for dns_sentinel (stubbed DNS hook, no network)."""

from aegis.engines.base import ScanContext
from aegis.engines.dns_sentinel import DnsSentinel

BASELINE = {
    "www.example.com": {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
        "MX": ["10 mail.example.com"],
        "TXT": ["v=spf1 include:_spf.example.com ~all"],
        "NS": ["ns1.example.com", "ns2.example.com"],
    }
}


def make_ctx(current, hosts=("www.example.com",)):
    def resolve(host, rtype):
        return list(current.get((host, rtype), []))

    return ScanContext(
        targets={"dns_hosts": list(hosts)},
        dns_resolve=resolve,
        data={"dns_baseline": BASELINE},
    )


def _current_from_baseline(overrides=None):
    cur = {}
    for host, rmap in BASELINE.items():
        for rtype, vals in rmap.items():
            cur[(host, rtype)] = list(vals)
    for key, vals in (overrides or {}).items():
        cur[key] = vals
    return cur


def test_no_drift_no_findings():
    ctx = make_ctx(_current_from_baseline())
    assert DnsSentinel().scan(ctx) == []


def test_a_record_change_scores_55():
    ctx = make_ctx(_current_from_baseline({("www.example.com", "A"): ["203.0.113.9"]}))
    findings = DnsSentinel().scan(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.score == 55
    assert f.severity == "medium"
    assert f.evidence["rtype"] == "A"
    assert f.evidence["added"] == ["203.0.113.9"]
    assert f.evidence["removed"] == ["93.184.216.34"]


def test_mx_change_scores_80():
    ctx = make_ctx(
        _current_from_baseline({("www.example.com", "MX"): ["10 mx.evil.test"]})
    )
    findings = DnsSentinel().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 80
    assert findings[0].severity == "high"


def test_ns_change_scores_80():
    ctx = make_ctx(
        _current_from_baseline({("www.example.com", "NS"): ["ns1.evil.test"]})
    )
    findings = DnsSentinel().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 80


def test_txt_change_scores_30():
    ctx = make_ctx(
        _current_from_baseline({("www.example.com", "TXT"): ["v=spf1 -all"]})
    )
    findings = DnsSentinel().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 30
    assert findings[0].severity == "low"


def test_new_host_scores_55():
    cur = _current_from_baseline()
    cur[("shadow.example.com", "A")] = ["198.51.100.7"]

    def resolve(host, rtype):
        return list(cur.get((host, rtype), []))

    ctx = ScanContext(
        targets={"dns_hosts": ["www.example.com", "shadow.example.com"]},
        dns_resolve=resolve,
        data={"dns_baseline": BASELINE},
    )
    findings = DnsSentinel().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 55
    assert findings[0].evidence["new_host"] is True


def test_new_host_with_no_records_no_finding():
    ctx = make_ctx(
        _current_from_baseline(), hosts=("www.example.com", "ghost.example.com")
    )
    assert DnsSentinel().scan(ctx) == []


def test_multiple_rtype_changes_multiple_findings():
    ctx = make_ctx(
        _current_from_baseline(
            {
                ("www.example.com", "A"): ["203.0.113.9"],
                ("www.example.com", "MX"): ["10 mx.evil.test"],
            }
        )
    )
    findings = DnsSentinel().scan(ctx)
    assert sorted(f.score for f in findings) == [55, 80]
