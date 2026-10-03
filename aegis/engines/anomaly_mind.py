"""Anomaly Mind — statistical anomaly detection on metric event rates.

The real attack: breaches show up as changes in rates. Logins per minute
spike during a password spray; egress traffic surges during data
exfiltration; DNS queries explode during tunneling — or a compromised
service goes *silent* when the attacker disables logging. This engine runs
an EWMA baseline plus a rolling z-score over each metric series and flags
statistically significant deviations, with dedicated flatline detection for
the go-quiet case.
"""

from __future__ import annotations

import math
import statistics

from aegis.engines import Engine, register
from aegis.engines.base import ScanContext

#: Minimum series length before any judgment is attempted.
MIN_POINTS = 10

#: Fixed z assigned to a deviation from a perfectly flat baseline (where a
#: true z-score is undefined). Kept at the default threshold so the
#: ``threshold`` option can still suppress it.
FLAT_BASELINE_Z = 3.0


@register
class AnomalyMind(Engine):
    """Flags statistical anomalies (spikes, drops, flatlines) in metric
    series via EWMA + rolling z-score."""

    name = "anomaly_mind"
    version = "1.0.0"
    description = (
        "Detects anomalous event-rate behavior with an EWMA baseline, "
        "rolling z-scores, and flatline (go-quiet) detection."
    )

    def scan(self, ctx: ScanContext) -> list:
        series_map: dict = ctx.data.get("series") or {}
        alpha: float = float(ctx.option("alpha", 0.3))
        window: int = int(ctx.option("window", 20))
        threshold: float = float(ctx.option("threshold", 3.0))

        findings: list = []
        for metric, raw in series_map.items():
            series = self._coerce(raw)
            if len(series) < MIN_POINTS:
                continue
            flatline = self._flatline(series, window)
            if flatline is not None:
                findings.append(flatline(metric, series))
                continue  # a flat series has no z-score to compute
            spike = self._worst_spike(metric, series, alpha, window, threshold)
            if spike is not None:
                findings.append(spike)
        return findings

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _coerce(raw) -> list[float]:
        out: list[float] = []
        for value in raw or []:
            try:
                out.append(float(value))
            except (TypeError, ValueError):
                continue
        return out

    def _ewma(self, series: list[float], alpha: float) -> float:
        baseline = series[0]
        for value in series[1:]:
            baseline = alpha * value + (1.0 - alpha) * baseline
        return baseline

    def _flatline(self, series: list[float], window: int):
        """std == 0 over the trailing window: the metric went quiet."""
        w = min(window, len(series))
        if w < MIN_POINTS:
            return None
        tail = series[-w:]
        if statistics.pstdev(tail) != 0.0:
            return None

        def make(metric: str, _series: list[float]):
            return self.finding(
                title=f"Metric flatlined: {metric}",
                score=15,
                entities={"metric": metric},
                evidence={
                    "expected": "varying values",
                    "observed": f"constant at {tail[0]}",
                    "window_points": w,
                },
                recommendation=(
                    f"{metric} stopped changing — check whether the source "
                    "stopped emitting, logging was disabled, or the sensor "
                    "died. Attackers silence logging before the loud part."
                ),
                tags=["anomaly", "flatline", metric],
            )

        return make

    def _worst_spike(
        self,
        metric: str,
        series: list[float],
        alpha: float,
        window: int,
        threshold: float,
    ):
        """Rolling z-score of each point against the *preceding* window;
        returns the single most extreme deviation, or None. A deviation
        from a perfectly flat baseline is always anomalous."""
        baseline = self._ewma(series, alpha)
        best = None  # (abs_z, z, expected, observed)
        for i in range(len(series)):
            hist = series[max(0, i - window) : i]
            if len(hist) < MIN_POINTS:
                continue
            mean = statistics.fmean(hist)
            std = statistics.pstdev(hist)
            observed = series[i]
            if std == 0.0:
                if observed == mean:
                    continue
                # Flat baseline, sudden move: anomalous by definition, but
                # the z is unquantifiable — report a fixed strong signal.
                z = math.copysign(FLAT_BASELINE_Z, observed - mean)
            else:
                z = (observed - mean) / std
            if abs(z) >= threshold and (best is None or abs(z) > best[0]):
                best = (abs(z), z, mean, observed)
        if best is None:
            return None
        abs_z, z, expected, observed = best
        return self.finding(
            title=f"Anomalous {metric}: z={z:+.1f}",
            score=min(95.0, 50.0 + abs_z * 10.0),
            entities={"metric": metric},
            evidence={
                "z": round(z, 2),
                "expected": round(expected, 2),
                "observed": observed,
                "ewma_baseline": round(baseline, 2),
                "threshold": threshold,
            },
            recommendation=(
                f"{metric} deviated {abs_z:.1f} sigma from baseline. "
                "Correlate the timestamp with auth, firewall, and egress "
                "logs before deciding if this is an attack or a launch."
            ),
            tags=["anomaly", metric],
        )
