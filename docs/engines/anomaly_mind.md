# anomaly_mind

Flags statistical anomalies — spikes, drops, and flatlines — in metric event-rate series.

## The attack it stops

At 2:40 a.m., a compromised service account starts exfiltrating a customer
database. Egress traffic from the app server jumps from a steady 40 MB/hour
to 9 GB/hour, and DNS queries triple as the malware tunnels data through
TXT lookups. Nothing in the firewall rules is "wrong" — the traffic is
allowed — but the *rates* are absurd. Then, at 3:05 a.m., the attacker kills
the logging agent to hide the cleanup phase, and the auth log metric goes
dead flat. Both deviations — the surge and the silence — were measurable in
the metrics stream. Nobody was watching the stream.

## How detection works

`anomaly_mind` is a `base.Engine` subclass registered with `@register`,
`name = "anomaly_mind"`. On `scan(ctx)` it reads metric series from
`ctx.data["series"]` — a mapping of `metric_name → [numeric values]` —
and evaluates each series independently. Non-numeric values are coerced or
dropped; series shorter than 10 points are skipped entirely.

Two detectors run per metric:

1. **Flatline detection**: if the trailing window (default 20 points) has
   zero population standard deviation, the metric went quiet → finding at
   15 (low), and the series is not z-scored further (a constant series has
   no variance to score against).
2. **Spike/dip detection**: an EWMA baseline (smoothing factor `alpha`,
   default 0.3) tracks the long-run level, and a rolling z-score is
   computed per point over its trailing window. The single most extreme
   deviation with `|z| ≥ threshold` (default 3.0) becomes a finding scored
   `min(95, 50 + |z| × 10)`.

Findings are built with `self.finding()`, which clamps scores and derives
severity from the standard bands. Evidence carries the z-score, expected
vs. observed values, EWMA baseline, and threshold.

## Scoring signals

- Spike/dip score = min(95, 50 + |z| × 10): z=3.0 → 80 (high); z=4.0 → 90
  (critical); anything beyond caps at 95 (critical). The z-score is the
  single knob — how far off-baseline the metric went.
- Flatline (15, low): the sensor went silent. Low severity because silence
  is often a dead collector, but the recommendation names the hostile
  cause too — attackers disable logging before the loud part.

Raising `threshold` (default 3.0) cuts noise on spiky-by-nature metrics;
raising `window` (default 20) smooths bursty series; lowering `alpha`
(default 0.3) makes the EWMA baseline slower to chase sustained changes.

## Configuration

```yaml
engines:
  anomaly_mind:
    enabled: true
    alpha: 0.3       # EWMA smoothing factor for the baseline
    window: 20       # rolling-window length (points) for z-scores
    threshold: 3.0    # |z| at or above this flags a spike/dip
```

Metric series are supplied with the scan as `ctx.data["series"]`
(metric name → list of numbers, ≥10 points).

## Sample finding

```json
{
  "id": "fnd_01K9Q2KH4J8TGEF6VLFI0BM0O",
  "engine": "anomaly_mind",
  "title": "Anomalous egress_bytes_per_min: z=+4.2",
  "severity": "critical",
  "score": 92.0,
  "entities": {
    "metric": "egress_bytes_per_min"
  },
  "evidence": {
    "z": 4.2,
    "expected": 1258291.2,
    "observed": 9663676416.0,
    "ewma_baseline": 1195376.6,
    "threshold": 3.0
  },
  "recommendation": "egress_bytes_per_min deviated 4.2 sigma from baseline. Correlate the timestamp with auth, firewall, and egress logs before deciding if this is an attack or a launch.",
  "tags": ["anomaly", "egress_bytes_per_min"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
