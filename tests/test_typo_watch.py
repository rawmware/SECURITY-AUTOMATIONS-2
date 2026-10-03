"""Hermetic tests for typo_watch (stubbed DNS/CT hooks, no network)."""

from aegis.engines.base import ScanContext
from aegis.engines.typo_watch import TypoWatch, generate_candidates


def make_ctx(dns=None, ct_log=None, brand="paypal.com", options=None):
    dns = dns or {}

    def resolve(host, rtype):
        return list(dns.get((host, rtype), []))

    return ScanContext(
        targets={"brand_domain": brand},
        options=options or {},
        dns_resolve=resolve,
        data={"ct_log": set(ct_log or set())},
    )


def test_candidates_include_homoglyph():
    cands = generate_candidates("paypal.com")
    assert "paypa1.com" in cands  # l -> 1


def test_candidates_include_tld_swap_and_hyphenation():
    cands = generate_candidates("paypal.com")
    assert "paypal.co" in cands
    assert "pay-pal.com" in cands


def test_candidates_include_double_letter_and_prefix():
    cands = generate_candidates("paypal.com")
    assert "payppal.com" in cands
    assert "login-paypal.com" in cands


def test_candidates_exclude_brand_itself():
    assert "paypal.com" not in generate_candidates("paypal.com")


def test_finding_emitted_on_a_record():
    ctx = make_ctx(dns={("paypa1.com", "A"): ["93.184.216.34"]})
    findings = TypoWatch().scan(ctx)
    hit = [f for f in findings if f.entities.get("domain") == "paypa1.com"]
    assert hit, "expected a finding for the resolving lookalike"
    # A(+30) only: brand keyword absent for paypa1 (homoglyph) -> score 30
    assert hit[0].score == 30


def test_scoring_math_all_signals():
    # A(+30) + MX(+25) + CT(+20) = 75
    # ("paypa1" is a homoglyph variant, so the brand keyword bonus does not apply)
    ctx = make_ctx(
        dns={("paypa1.com", "A"): ["1.1.1.1"], ("paypa1.com", "MX"): ["mx.evil.test"]},
        ct_log={"paypa1.com"},
    )
    findings = TypoWatch().scan(ctx)
    hit = [f for f in findings if f.entities.get("domain") == "paypa1.com"][0]
    assert hit.score == 75
    assert hit.severity == "high"
    assert hit.evidence["score_breakdown"] == {
        "resolves_a": 30,
        "resolves_mx": 25,
        "in_ct_log": 20,
    }


def test_scoring_math_brand_keyword_bonus():
    # "login-paypal.com" keeps the literal brand label: A(+30) + keyword(+10) = 40
    ctx = make_ctx(dns={("login-paypal.com", "A"): ["1.1.1.1"]})
    findings = TypoWatch().scan(ctx)
    hit = [f for f in findings if f.entities.get("domain") == "login-paypal.com"][0]
    assert hit.score == 40
    assert hit.evidence["score_breakdown"]["brand_keyword"] == 10


def test_no_finding_when_no_signals():
    ctx = make_ctx()  # empty DNS, empty CT log
    assert TypoWatch().scan(ctx) == []


def test_min_score_option_filters():
    ctx = make_ctx(
        dns={("paypa1.com", "A"): ["1.1.1.1"]},
        options={"min_score": 90},
    )
    assert TypoWatch().scan(ctx) == []


def test_max_candidates_option_truncates():
    seen = []

    def resolve(host, rtype):
        seen.append(host)
        return ["9.9.9.9"] if rtype == "A" else []

    ctx = ScanContext(
        targets={"brand_domain": "paypal.com"},
        options={"max_candidates": 3},
        dns_resolve=resolve,
        data={"ct_log": set()},
    )
    findings = TypoWatch().scan(ctx)
    assert len(findings) == 3
    assert len(set(seen)) == 3


def test_registered():
    from aegis.engines import get_engine

    assert get_engine("typo_watch") is TypoWatch
