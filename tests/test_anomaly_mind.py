"""Hermetic tests for anomaly_mind."""

from aegis.engines.base import ScanContext
from aegis.engines.anomaly_mind import AnomalyMind


def ctx(series_map, **options):
    return ScanContext(data={"series": series_map}, options=options)


def test_spike_flagged():
    series = [10.0] * 15 + [100.0]
    f = AnomalyMind().scan(ctx({"logins_per_min": series}))
    assert len(f) == 1
    ev = f[0].evidence
    assert ev["observed"] == 100.0
    assert ev["z"] >= 3.0
    assert ev["expected"] < 50.0
    assert f[0].score == min(95.0, 50.0 + abs(ev["z"]) * 10.0)


def test_drop_flagged():
    series = [500.0] * 15 + [5.0]
    f = AnomalyMind().scan(ctx({"egress_mbps": series}))
    assert len(f) == 1
    assert f[0].evidence["z"] <= -3.0


def test_flatline_informational():
    series = [7.0] * 25
    f = AnomalyMind().scan(ctx({"heartbeat": series}))
    assert len(f) == 1
    assert f[0].score == 15
    # NOTE: spec asked for "informational", but the shared SCORE_BANDS map
    # score 15 -> "low" (informational is 0-<10). Score kept at 15 per spec;
    # severity follows the shared bands. Flagged to parent.
    assert f[0].severity == "low"
    assert "flatlined" in f[0].title


def test_steady_noisy_series_clean():
    series = [100.0, 102.0, 98.0, 101.0, 99.0, 103.0, 97.0, 100.0,
              101.0, 99.0, 100.0, 102.0, 98.0, 100.0, 101.0, 99.0]
    f = AnomalyMind().scan(ctx({"requests": series}))
    assert f == []


def test_short_series_skipped():
    f = AnomalyMind().scan(ctx({"x": [1.0, 2.0, 3.0]}))
    assert f == []


def test_threshold_option_suppresses():
    series = [10.0] * 15 + [100.0]
    f = AnomalyMind().scan(ctx({"logins_per_min": series}, threshold=99.0))
    assert f == []


def test_score_formula_caps_at_95():
    # noisy (non-flat) baseline + enormous spike -> raw score exceeds 95
    baseline = [10.0, 12.0, 9.0, 11.0, 10.5, 9.5, 11.5, 10.0, 12.0, 9.0, 11.0, 10.5]
    f = AnomalyMind().scan(ctx({"x": baseline + [100000.0]}))
    assert len(f) == 1
    assert f[0].score == 95
    assert f[0].evidence["z"] > 4.5


def test_one_finding_per_metric_worst_point():
    series = [10.0] * 15 + [200.0, 100.0]
    f = AnomalyMind().scan(ctx({"logins_per_min": series}))
    assert len(f) == 1
    assert f[0].evidence["observed"] == 200.0


def test_empty_series_map():
    assert AnomalyMind().scan(ScanContext(data={})) == []


def test_flatline_requires_min_window():
    # 8 points: too short for any judgment at all
    f = AnomalyMind().scan(ctx({"x": [3.0] * 8}))
    assert f == []
