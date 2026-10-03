"""Hermetic tests for tls_watch."""

from datetime import datetime, timedelta, timezone

from aegis.engines.base import ScanContext
from aegis.engines.tls_watch import TlsWatch

NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


def iso(days_from_now):
    return (NOW + timedelta(days=days_from_now)).isoformat()


def make_ctx(certs):
    return ScanContext(
        now_iso=lambda: NOW.isoformat(),
        data={"tls_certs": certs},
    )


def good_cert(**kw):
    cert = {
        "host": "www.example.com",
        "not_after": iso(400),
        "sig_alg": "sha256WithRSAEncryption",
        "key_bits": 2048,
        "san_ok": True,
    }
    cert.update(kw)
    return cert


def test_expiry_under_14_days_scores_95():
    ctx = make_ctx([good_cert(not_after=iso(10))])
    findings = TlsWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 95
    assert findings[0].severity == "critical"


def test_expired_cert_scores_95():
    ctx = make_ctx([good_cert(not_after=iso(-2))])
    findings = TlsWatch().scan(ctx)
    assert findings and findings[0].score == 95


def test_expiry_under_30_days_scores_80():
    ctx = make_ctx([good_cert(not_after=iso(20))])
    findings = TlsWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 80
    assert findings[0].severity == "high"


def test_expiry_under_60_days_scores_55():
    ctx = make_ctx([good_cert(not_after=iso(45))])
    findings = TlsWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 55
    assert findings[0].severity == "medium"


def test_weak_sig_alg_scores_75():
    ctx = make_ctx([good_cert(sig_alg="sha1WithRSAEncryption")])
    findings = TlsWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 75


def test_undersized_key_scores_70():
    ctx = make_ctx([good_cert(key_bits=1024)])
    findings = TlsWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 70


def test_san_mismatch_scores_50():
    ctx = make_ctx([good_cert(san_ok=False)])
    findings = TlsWatch().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 50


def test_clean_cert_no_findings():
    assert TlsWatch().scan(make_ctx([good_cert()])) == []


def test_multiple_problems_one_finding_each():
    ctx = make_ctx(
        [
            good_cert(
                not_after=iso(10),
                sig_alg="md5WithRSAEncryption",
                key_bits=1024,
                san_ok=False,
            )
        ]
    )
    findings = TlsWatch().scan(ctx)
    assert sorted(f.score for f in findings) == [50, 70, 75, 95]


def test_days_remaining_in_evidence():
    ctx = make_ctx([good_cert(not_after=iso(10))])
    f = TlsWatch().scan(ctx)[0]
    assert f.evidence["days_remaining"] == 10.0
    assert f.entities["host"] == "www.example.com"
