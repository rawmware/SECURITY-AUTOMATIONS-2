"""Tests for aegis.runner.ScanRunner against the real engine fleet."""

from __future__ import annotations

from aegis.bus import Bus
from aegis.config import AegisConfig
from aegis.engines import get_engine
from aegis.models import Finding, ScoredFinding
from aegis.runner import ScanRunner
from tests.conftest import typo_sim


def test_run_executes_engines_and_returns_findings():
    targets, sim_data = typo_sim()
    result = ScanRunner(AegisConfig()).run(targets=targets, sim_data=sim_data)
    assert "typo_watch" in result["engines_run"]
    assert result["findings"], "expected findings from typo_watch"
    assert all(isinstance(f, Finding) for f in result["findings"])
    assert all(f.engine == "typo_watch" for f in result["findings"])
    assert result["errors"] == []


def test_build_context_merges_targets_and_sim_data():
    runner = ScanRunner(AegisConfig(brand_domain="base.test"))
    ctx = runner.build_context(
        targets={"brand_domain": "acme.test", "asn": 64500},
        sim_data={"k": "v"},
    )
    assert ctx.targets["brand_domain"] == "acme.test"
    assert ctx.targets["asn"] == 64500
    assert ctx.data["k"] == "v"


def test_engine_error_isolation(monkeypatch):
    """One raising engine must not kill the run; the error is recorded."""
    cls = get_engine("canary_trip")

    def boom(self, ctx):
        raise RuntimeError("simulated engine failure")

    monkeypatch.setattr(cls, "scan", boom)
    targets, sim_data = typo_sim()
    result = ScanRunner(AegisConfig()).run(targets=targets, sim_data=sim_data)
    assert "canary_trip" in result["engines_run"]
    assert any(e["engine"] == "canary_trip" for e in result["errors"])
    assert any(f.engine == "typo_watch" for f in result["findings"])


def test_dedupe_integration_collapses_duplicates(monkeypatch):
    """Identical findings from one engine collapse to a single scored item."""
    cls = get_engine("typo_watch")

    def fake_scan(self, ctx):
        f = self.finding("Duplicate probe", 50.0, entities={"domain": "dup.test"})
        return [f, f]

    monkeypatch.setattr(cls, "scan", fake_scan)
    result = ScanRunner(AegisConfig()).run()
    assert len(result["findings"]) == 2, "raw findings keep duplicates"
    assert len(result["scored"]) == 1, "dedupe should collapse identical findings"


def test_bus_publish_received():
    bus = Bus()
    received: list[Finding] = []
    bus.subscribe("findings", received.append)
    targets, sim_data = typo_sim()
    ScanRunner(AegisConfig(), bus=bus).run(targets=targets, sim_data=sim_data)
    assert received, "expected the runner to publish findings to the bus"
    assert received[0].engine == "typo_watch"


def test_disabled_engine_is_skipped():
    config = AegisConfig(engines={"typo_watch": {"enabled": False}})
    targets, sim_data = typo_sim()
    result = ScanRunner(config).run(targets=targets, sim_data=sim_data)
    assert "typo_watch" not in result["engines_run"]
    assert not any(f.engine == "typo_watch" for f in result["findings"])


def test_scored_findings_wrap_with_adjusted_scores():
    targets, sim_data = typo_sim()
    result = ScanRunner(AegisConfig()).run(targets=targets, sim_data=sim_data)
    assert len(result["scored"]) == 2
    for scored in result["scored"]:
        assert isinstance(scored, ScoredFinding)
        assert 0.0 <= scored.adjusted_score <= 100.0
        assert scored.adjusted_severity in (
            "informational", "low", "medium", "high", "critical",
        )
        assert scored.factors, "score stage should record its factors"
