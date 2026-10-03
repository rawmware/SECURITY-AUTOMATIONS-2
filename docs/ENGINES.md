# Aegis 2.0.0 — Detection Engines

Twelve engines, one contract: subclass `Engine` in `aegis/engines/`, set
`name`/`description`, implement `scan(ctx) -> list[Finding]`, register with
`@register`. Use `self.finding(title, score, entities, evidence,
recommendation, tags)` — it clamps the score to 0–100 and derives the
severity for you.

## The fleet

| engine | what it catches | why it matters |
|---|---|---|
| `typo_watch` | Lookalike registrations of the brand domain, generated from 12 squatting techniques and checked via DNS + certificate-transparency signals | Most phishing starts with a domain that looks like yours; this finds it before the campaign does |
| `dns_sentinel` | Drift of watched hosts' DNS records against a baseline — NS/MX changes, A/AAAA rerouting, TXT changes | Stale or hijacked DNS silently redirects your traffic and mail to an attacker |
| `tls_watch` | Expiring certificates, weak signature algorithms (SHA-1/MD5), undersized keys, SAN/hostname mismatch | An expired or mis-issued cert is an outage or a spoof waiting to happen |
| `port_watch` | Unexpected open ports vs. baseline; expected-but-closed ports | A new open port is usually a new door; a missing expected one is an availability problem |
| `auth_watch` | Brute-force (many fails, one IP), password spray (many users, one IP), distributed attacks (one user, many IPs) | Credential attacks are the cheapest way in and the noisiest signal to catch |
| `url_intel` | Malicious URLs via redirect chains, punycode, IP hosts, @-injection, shady TLDs, phishing keywords, redirect depth | Links are the delivery mechanism for nearly every phishing and malware campaign |
| `secret_sentry` | Leaked secrets (cloud keys, PATs, private keys, API tokens) in text, via high-signal patterns plus an entropy gate | A leaked credential is instant compromise; catching it in minutes vs. months decides the outcome |
| `cve_watch` | Installed dependency versions matched against known CVEs by package name and affected-version spec | Unpatched dependencies are the most common remote-exploit path |
| `cloud_posture` | Public S3 buckets, world-open security-group ingress on sensitive ports, wildcard IAM actions, unencrypted volumes | Cloud misconfigurations are public by default and scanned by attackers within hours |
| `phish_kit` | Pages matching phishing-kit fingerprints — credential harvesters, Telegram exfil, obfuscated JS, hidden iframes, brand impersonation | Kit fingerprints catch the attacker's tooling, not just one URL |
| `anomaly_mind` | Anomalous event-rate behavior via EWMA baselines, rolling z-scores, and flatline (go-quiet) detection | Baselines catch what signatures can't — including logs that suddenly stop, which is often the first sign of compromise |
| `canary_trip` | Honeytoken tripwires — a planted canary token seen in sightings | A canary firing means an intruder already touched something; there is no false-positive version of that |

## Scoring philosophy

Every engine emits a 0–100 score per finding. The mapping from score to
severity is fixed in `aegis/models.py::severity_for_score` and shared by
everyone:

| score | severity |
|---|---|
| ≥ 90 | critical |
| ≥ 70 | high |
| ≥ 40 | medium |
| ≥ 10 | low |
| < 10 | informational |

An unknown severity string raises `ValueError` — severities are closed, not
free text. Scores are clamped to 0–100 by `clamp()` in the `finding()` helper,
and `to_dict()` rounds the score to one decimal place.

- **Engines score confidence × impact.** The score answers one question: how
  worried should a reasonable operator be about this thing, right now? It is
  not a CVSS, not a probability, not a count.
- **The pipeline adjusts for asset context.** The raw engine score is the
  starting point; the scoring stage produces `adjusted_score` using asset
  criticality, confidence, and business context, with every adjustment
  recorded in the `factors` dict and severity re-derived from the bands
  (see `PIPELINE.md`). Engines stay ignorant of your business; the pipeline
  is where business context lives.
- **No silent defaults.** An engine must justify its score in `evidence`:
  what it observed, what threshold it crossed, what it compared against.
  A finding with an empty evidence dict is a bug — if the engine cannot say
  why the score is what it is, the score should not exist.

Engine options live in `aegis.yml` under `engines.<engine_id>` (e.g.
`auth_watch.fail_threshold`, `typo_watch.max_candidates`). See
`aegis.example.yml` for the full list, and `DEPLOYMENT.md` for config
reference.

## Writing an engine

Subclass `Engine`, register it, keep it stdlib-only:

```python
from aegis.engines import register
from aegis.engines.base import Engine, ScanContext
from aegis.models import Finding

@register
class MyEngine(Engine):
    name = "my_engine"
    version = "1.0.0"
    description = "What it catches, in one sentence."

    def scan(self, ctx: ScanContext) -> list[Finding]:
        for host in ctx.targets.get("hosts", []):
            records = ctx.dns_resolve(host, "A")  # injected I/O, never raw
            if not records:
                return [self.finding(
                    title=f"No A records for {host}",
                    score=55,
                    entities={"host": host},
                    evidence={"records": records},
                    recommendation="Check whether the host was decommissioned.",
                    tags=["dns", "availability"],
                )]
        return []
```

Rules: no raw socket or file I/O (use `ctx.dns_resolve`, `ctx.http_get`,
`ctx.read_file`); scenario inputs come from `ctx.data`, which is what lets
tests and the demo simulate the internet. Raise nothing on bad input —
return an empty list and let the runner record the failure. Keep `scan()`
fast: the runner executes engines sequentially, and a slow engine slows
every scan.

## Engine isolation

The runner catches exceptions per engine and records them in the scan
result's `errors` list. One crashing engine never aborts the scan and never
takes down the API — `POST /scan` returns findings from the engines that
succeeded alongside the error record. If an engine is misbehaving in
production, disable it in `aegis.yml` (`engines.<id>.enabled: false`) and
restart; no code change needed.
