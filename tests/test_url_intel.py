"""Hermetic tests for url_intel (stubbed http_get hook, no network)."""

from aegis.engines.base import ScanContext
from aegis.engines.url_intel import UrlIntel


def make_ctx(urls, redirects_map=None, options=None):
    redirects_map = redirects_map or {}

    def http_get(url):
        return {"redirects": list(redirects_map.get(url, []))}

    return ScanContext(options=options or {}, http_get=http_get, data={"urls": urls})


def test_clean_url_no_finding():
    ctx = make_ctx(["https://www.example.com/about"])
    assert UrlIntel().scan(ctx) == []


def test_ip_host_scores_30_below_threshold():
    ctx = make_ctx(["http://192.0.2.10/status"])
    assert UrlIntel().scan(ctx) == []  # 30 < 40


def test_ip_host_plus_keyword_reaches_threshold():
    # ip_host(+30) + keyword(+10) = 40 -> finding
    ctx = make_ctx(["http://192.0.2.10/login"])
    findings = UrlIntel().scan(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.score == 40
    assert f.severity == "medium"
    assert f.evidence["score_breakdown"] == {"ip_host": 30, "phish_keywords": 10}


def test_punycode_and_shady_tld():
    # punycode(+25) + shady_tld(+15) + keyword "verify"(+10) = 50 -> finding
    ctx = make_ctx(["http://xn--pypal-4ve.top/verify"])
    findings = UrlIntel().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 50


def test_at_injection_plus_two_keywords():
    # @(+20) + 2 keywords(+20) = 40 -> finding
    ctx = make_ctx(["https://realbank.com@evil.test/login/verify"])
    findings = UrlIntel().scan(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["score_breakdown"]["at_in_netloc"] == 20
    assert findings[0].evidence["score_breakdown"]["phish_keywords"] == 20


def test_keyword_cap_at_20():
    # three keywords would be 30, capped at 20
    ctx = make_ctx(["http://192.0.2.10/login/verify/wallet"])
    findings = UrlIntel().scan(ctx)
    assert findings[0].score == 50  # 30 ip + 20 capped keywords


def test_redirect_chain_adds_15():
    short = "https://bit.ly/login-help"
    ctx = make_ctx(
        [short],
        redirects_map={short: ["https://t.co/x", "https://evil.test/login"]},
        options={"min_score": 20},
    )
    findings = UrlIntel().scan(ctx)
    assert len(findings) == 1
    f = findings[0]
    # keyword(+10) + redirect_chain(+15) = 25
    assert f.score == 25
    assert f.evidence["score_breakdown"]["redirect_chain"] == 15
    assert f.evidence["redirect_hops"] == 2
    assert f.entities["final_url"] == "https://evil.test/login"


def test_long_query_adds_10():
    url = "https://example.com/search?" + "q=" + "x" * 130
    ctx = make_ctx([url])
    # long_query(+10) only -> 10 < 40, no finding
    assert UrlIntel().scan(ctx) == []


def test_min_score_option_override():
    ctx = make_ctx(["http://192.0.2.10/status"], options={"min_score": 25})
    findings = UrlIntel().scan(ctx)
    assert len(findings) == 1
    assert findings[0].score == 30


def test_score_capped_at_100():
    url = (
        "http://192.0.2.10@xn--evil-4ve.zip/login/verify/wallet?"
        + "q=" + "x" * 130
        + "&pad=" + "y" * 100
    )
    ctx = make_ctx([url], redirects_map={url: ["https://a.test", "https://b.test"]})
    findings = UrlIntel().scan(ctx)
    assert findings[0].score <= 100
    assert findings[0].severity == "critical"
