"""Hermetic tests for the aegis.pipeline stages."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.config import AegisConfig
from aegis.models import Finding, ScoredFinding
from aegis.pipeline import (
    Deduper,
    chain_stage,
    correlate,
    enrich,
    format_discord,
    format_slack,
    normalize_event,
    route,
    score_finding,
)

UTC = timezone.utc


def make_finding(
    engine="auth_watch",
    title="many failed logins",
    severity="high",
    score=80.0,
    entities=None,
    evidence=None,
    ts=None,
):
    return Finding(
        engine=engine,
        title=title,
        severity=severity,
        score=score,
        entities=dict(entities or {"ip": "203.0.113.9", "host": "web-01"}),
        evidence=dict(evidence or {"failures": 42}),
        recommendation="Block the source IP.",
        ts=ts or datetime(2026, 10, 3, 12, 0, tzinfo=UTC),
    )


def make_scored(finding=None, score=90.6, severity="critical"):
    f = finding or make_finding()
    return ScoredFinding(
        finding=f,
        adjusted_score=score,
        adjusted_severity=severity,
        factors={"base_score": f.score},
    )


# -- normalize ------------------------------------------------------------
def test_normalize_fills_defaults():
    event = normalize_event({"src": "edge-fw-1"})
    assert event["source"] == "edge-fw-1"
    assert event["kind"] == ""
    assert event["entities"] == {}
    assert event["raw"] == {"src": "edge-fw-1"}
    now = datetime.now(UTC)
    assert abs((now - event["ts"]).total_seconds()) < 5


def test_normalize_parses_iso_ts():
    event = normalize_event({"timestamp": "2026-10-03T12:00:00Z"})
    assert event["ts"] == datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


def test_normalize_lowercases_kind_and_maps_keys():
    event = normalize_event(
        {"type": "BruteForce", "entities": {"ip": "1.2.3.4"}}
    )
    assert event["kind"] == "bruteforce"
    assert event["entities"] == {"ip": "1.2.3.4"}


def test_normalize_coerces_non_dict_entities():
    event = normalize_event({"entities": "203.0.113.9"})
    assert event["entities"] == {"value": "203.0.113.9"}


# -- enrich ---------------------------------------------------------------
def test_enrich_crown_jewel():
    finding = make_finding(entities={"host": "db-01"})
    result = enrich(finding, {"db-01": 5})
    assert result == {
        "asset_criticality": 5,
        "is_crown_jewel": True,
        "entity_count": 1,
    }


def test_enrich_defaults_unknown_entities_to_2():
    finding = make_finding(entities={"ip": "10.0.0.7", "host": "web-01"})
    result = enrich(finding, {"web-01": 3})
    assert result["asset_criticality"] == 3
    assert result["is_crown_jewel"] is False
    assert result["entity_count"] == 2


# -- score ----------------------------------------------------------------
def test_score_math():
    finding = make_finding(score=80.0)
    scored = score_finding(finding, {"asset_criticality": 4}, confidence=0.9)
    assert scored.adjusted_score == 90.6
    assert scored.adjusted_severity == "critical"
    assert scored.factors["base_score"] == 80.0
    assert scored.factors["criticality"] == 4
    assert scored.factors["confidence"] == 0.9
    assert scored.factors["multiplier"] == pytest.approx(1.133, abs=1e-3)


def test_score_clamps_to_100():
    finding = make_finding(score=100.0)
    scored = score_finding(finding, {"asset_criticality": 5}, confidence=1.0)
    assert scored.adjusted_score == 100.0
    assert scored.adjusted_severity == "critical"


# -- correlate ------------------------------------------------------------
def _brute_force_group(base):
    return [
        make_scored(
            make_finding(
                engine="typo_watch",
                title="lookalike domain registered",
                score=70,
                entities={"host": "web-01"},
                ts=base,
            ),
            score=72.0,
            severity="high",
        ),
        make_scored(
            make_finding(
                engine="auth_watch",
                title="password spraying",
                score=80,
                entities={"host": "web-01", "user": "admin"},
                ts=base + timedelta(minutes=5),
            ),
            score=90.6,
            severity="critical",
        ),
        make_scored(
            make_finding(
                engine="auth_watch",
                title="brute-force burst",
                score=85,
                entities={"host": "web-01", "user": "admin"},
                ts=base + timedelta(minutes=10),
            ),
            score=94.0,
            severity="critical",
        ),
        make_scored(
            make_finding(
                engine="url_intel",
                title="malicious login page",
                score=75,
                entities={"host": "web-01"},
                ts=base + timedelta(minutes=15),
            ),
            score=78.0,
            severity="high",
        ),
    ]


def test_correlate_groups_shared_entity_into_one_case():
    cases = correlate(_brute_force_group(datetime(2026, 10, 3, 12, 0, tzinfo=UTC)))
    assert len(cases) == 1
    case = cases[0]
    assert case.title == "Coordinated brute-force against web-01 (4 findings)"
    assert case.score == pytest.approx(100.0)  # min(100, 94 + 5*3)
    assert case.severity == "critical"
    assert len(case.findings) == 4


def test_correlate_splits_by_window_and_entity():
    base = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    group = _brute_force_group(base)
    far = make_scored(
        make_finding(
            engine="auth_watch",
            entities={"host": "web-01"},
            ts=base + timedelta(hours=3),
        ),
        score=80.0,
        severity="high",
    )
    unrelated = make_scored(
        make_finding(
            engine="port_watch",
            title="new open port",
            entities={"host": "db-02"},
            ts=base + timedelta(minutes=8),
        ),
        score=55.0,
        severity="medium",
    )
    cases = correlate(group + [far, unrelated])
    assert len(cases) == 3


def test_correlate_narrative_names_entities_and_kill_chain():
    cases = correlate(_brute_force_group(datetime(2026, 10, 3, 12, 0, tzinfo=UTC)))
    narrative = cases[0].narrative
    assert "web-01" in narrative
    assert "recon" in narrative
    assert "initial access" in narrative
    assert narrative.index("recon") < narrative.index("initial access")
    assert len(narrative.split(". ")) >= 2


def test_chain_stage_mapping():
    assert chain_stage(make_finding(engine="typo_watch")) == "recon"
    assert chain_stage(make_finding(engine="auth_watch")) == "initial access"
    assert chain_stage(make_finding(engine="secret_sentry")) == "credential access"
    assert chain_stage(make_finding(engine="nope_watch")) == "unknown"


# -- dedupe ---------------------------------------------------------------
def test_dedupe_flags_repeat():
    deduper = Deduper()
    finding = make_finding()
    assert deduper.is_duplicate(finding) is False
    assert deduper.is_duplicate(finding) is True
    # different entity value → different fingerprint → not a duplicate
    other = make_finding(entities={"ip": "198.51.100.2", "host": "web-01"})
    assert deduper.is_duplicate(other) is False


def test_dedupe_window_expiry():
    deduper = Deduper(window_minutes=60)
    fp = deduper.fingerprint(make_finding())
    t0 = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    assert deduper.seen(fp, t0) is False
    assert deduper.seen(fp, t0 + timedelta(minutes=30)) is True
    # after the window expires the fingerprint is forgotten
    assert deduper.seen(fp, t0 + timedelta(minutes=61)) is False


# -- alert ----------------------------------------------------------------
def test_alert_threshold_filtering():
    cfg = AegisConfig(alert_threshold=70.0)
    sent = []
    alerts = route(
        [make_scored(score=90.6, severity="critical"), make_scored(score=50.0, severity="medium")],
        cfg,
        lambda alert: sent.append(alert) or True,
    )
    assert len(alerts) == 1
    assert len(sent) == 1
    assert alerts[0].delivered is True
    assert alerts[0].severity == "critical"


def test_alert_subject_body_and_failed_delivery():
    cfg = AegisConfig(alert_threshold=40.0)
    alerts = route(
        [make_scored(score=90.6, severity="critical")],
        cfg,
        lambda alert: False,
    )
    alert = alerts[0]
    assert alert.subject == "[AEGIS] critical: many failed logins"
    assert "many failed logins" in alert.body
    assert "Recommendation: Block the source IP." in alert.body
    assert "failures" in alert.body
    assert alert.delivered is False
    assert alert.channel == "webhook"


def test_format_slack_and_discord():
    scored = make_scored(score=90.6, severity="critical")
    slack = format_slack(scored)
    assert slack["text"].startswith("[AEGIS] critical:")
    assert any(b["type"] == "header" for b in slack["blocks"])
    discord = format_discord(scored)
    embed = discord["embeds"][0]
    assert embed["title"].startswith("[AEGIS] critical:")
    assert embed["color"] == 0xFF3B30
    assert any(f["name"] == "Recommendation" for f in embed["fields"])
