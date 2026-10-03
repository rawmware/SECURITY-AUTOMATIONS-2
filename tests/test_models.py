"""Tests for aegis.models: severity bands, Finding validation/clamping,
and the to_dict() shapes every downstream consumer relies on."""

from datetime import datetime

import pytest

from aegis.models import (
    SEVERITIES,
    Alert,
    Case,
    Finding,
    PlaybookRun,
    ScoredFinding,
    severity_for_score,
)


@pytest.mark.parametrize(
    "score,expected",
    [
        (100.0, "critical"),
        (95.0, "critical"),
        (90.0, "critical"),  # band edge, inclusive
        (89.9, "high"),
        (70.0, "high"),  # band edge, inclusive
        (69.9, "medium"),
        (40.0, "medium"),  # band edge, inclusive
        (39.9, "low"),
        (10.0, "low"),  # band edge, inclusive
        (9.9, "informational"),
        (0.0, "informational"),
    ],
)
def test_severity_for_score_bands(score, expected):
    assert severity_for_score(score) == expected


def test_severities_constant_order():
    assert SEVERITIES == ("informational", "low", "medium", "high", "critical")


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding(engine="typo_watch", title="t", severity="catastrophic", score=99)


@pytest.mark.parametrize(
    "raw,clamped",
    [(150.0, 100.0), (200, 100.0), (-5.0, 0.0), (-0.1, 0.0), (42.0, 42.0)],
)
def test_finding_score_clamped(raw, clamped):
    f = Finding(engine="dns_sentinel", title="t", severity="medium", score=raw)
    assert f.score == clamped


def test_finding_defaults():
    f = Finding(engine="tls_watch", title="t", severity="low", score=15.0)
    assert f.entities == {}
    assert f.evidence == {}
    assert f.recommendation == ""
    assert f.tags == []
    assert isinstance(f.ts, datetime)
    assert f.ts.tzinfo is not None  # timezone-aware UTC


def test_finding_ids_unique():
    f1 = Finding(engine="port_watch", title="a", severity="low", score=12)
    f2 = Finding(engine="port_watch", title="b", severity="low", score=12)
    assert f1.id.startswith("fnd-")
    assert f1.id != f2.id


def test_finding_to_dict_shape():
    f = Finding(
        engine="typo_watch",
        title="Lookalike domain registered: exarnple-secure.com",
        severity="critical",
        score=94.24,
        entities={"domain": "exarnple-secure.com"},
        evidence={"variant": "rn-for-m", "registered": True},
        recommendation="File takedown request with the registrar.",
        tags=["typosquat", "brand-abuse"],
    )
    d = f.to_dict()
    assert set(d) == {
        "id",
        "engine",
        "title",
        "severity",
        "score",
        "entities",
        "evidence",
        "recommendation",
        "tags",
        "ts",
    }
    assert d["engine"] == "typo_watch"
    assert d["severity"] == "critical"
    assert d["score"] == 94.2  # rounded to 1 decimal
    assert d["entities"] == {"domain": "exarnple-secure.com"}
    assert d["tags"] == ["typosquat", "brand-abuse"]
    assert isinstance(d["ts"], str)


def test_scored_finding_to_dict_shape():
    f = Finding(
        engine="auth_watch",
        title="Password spray detected",
        severity="high",
        score=80.0,
    )
    sf = ScoredFinding(
        finding=f,
        adjusted_score=85.55,
        adjusted_severity="high",
        factors={"asset_criticality": 1.1, "confidence": 0.9},
    )
    d = sf.to_dict()
    assert d["adjusted_score"] == 85.5  # round(85.55, 1) per CPython float repr
    assert d["adjusted_severity"] == "high"
    assert d["score_factors"] == {"asset_criticality": 1.1, "confidence": 0.9}
    assert d["engine"] == "auth_watch"  # base finding fields preserved
    assert d["id"] == f.id


def test_case_to_dict_shape():
    f1 = Finding(
        engine="canary_trip",
        title="Canary token touched",
        severity="critical",
        score=95.0,
    )
    f2 = Finding(
        engine="auth_watch", title="Spray from same IP", severity="high", score=80.0
    )
    c = Case(
        title="Active intrusion campaign",
        findings=[f1, f2],
        severity="critical",
        score=96.0,
        entities={"ip": "203.0.113.9"},
        narrative="Spray followed by canary trip within 20 minutes.",
        status="open",
    )
    d = c.to_dict()
    assert set(d) == {
        "id",
        "title",
        "severity",
        "score",
        "status",
        "entities",
        "narrative",
        "finding_ids",
        "ts",
    }
    assert d["finding_ids"] == [f1.id, f2.id]
    assert d["status"] == "open"
    assert d["id"].startswith("case-")


def test_alert_defaults_undelivered():
    a = Alert(target="#soc", channel="slack", subject="High finding", body="details")
    assert a.delivered is False
    assert a.severity == "medium"
    d = a.to_dict()
    assert set(d) == {
        "id",
        "channel",
        "target",
        "subject",
        "severity",
        "delivered",
        "ts",
    }
    assert d["id"].startswith("alrt-")


def test_playbook_run_dry_run_default():
    r = PlaybookRun(playbook="typo-takedown", trigger={"finding_id": "fnd-abc"})
    assert r.dry_run is True  # dry-run-by-default is a safety invariant
    assert r.status == "completed"
    assert r.steps == []
    d = r.to_dict()
    assert set(d) == {"id", "playbook", "dry_run", "status", "trigger", "steps", "ts"}
    assert d["id"].startswith("run-")
