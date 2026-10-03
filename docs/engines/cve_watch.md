# cve_watch

Matches installed dependency versions (SBOM) against a CVE feed; findings are CVSS-gated.

## The attack it stops

A regional logistics company runs a customer portal built on a web
framework version from 2023 with a known remote-code-execution flaw —
patched upstream two years ago, never applied here. A botnet sweeps the
internet for the vulnerable version string, finds the portal in an
afternoon, and drops ransomware across the company's file shares the
same night. Operations are
down for six days; the ransom demand is the least of the cost. The patch
existed before the attacker did.

## How detection works

`cve_watch` is a `base.Engine` subclass registered with `@register`,
`name = "cve_watch"`. On `scan(ctx)` it reads two inputs from the context
data: `ctx.data["sbom"]` — the software bill of materials (component
`name` + `version`) — and `ctx.data["cve_feed"]` — entries with `cve_id`,
`package`, `affected` version spec, `cvss`, `fixed_in`, and `summary`.

Installed packages are indexed by lowercase name (first entry wins). Each
feed entry whose package name matches an installed component is evaluated
with `version_matches()`, which parses version strings into integer tuples
(`1.2.3-beta` → `(1, 2, 3)`) and evaluates affected specs with `<`, `<=`,
`==` operators and comma-separated conjunctions (e.g.
`>=1.0,<2.4.1`-style ranges). On a match the finding score is `cvss * 10`,
clamped to 100 by `self.finding()`, and severity follows the standard
bands. Duplicate `package@version:CVE` pairs are emitted only once. The
engine performs no network I/O — the feed is supplied with the scan.

## Scoring signals

The score is derived, not assigned: `score = CVSS × 10`, clamped to 100.

- CVSS 9.0–10.0 → 90–100 (critical): network-exploitable RCE class — the
  patch-before-attacker case. Patch now.
- CVSS 7.0–8.9 → 70–89 (high): serious but often needs local access or
  user interaction — schedule promptly.
- CVSS 4.0–6.9 → 40–69 (medium): real but constrained — normal patch cadence.
- Below 4.0 → low/informational: still listed, but noisy for alerting.

Only exact name matches on *installed* components are checked — a CVE for
a library you don't ship never fires. Version parsing strips non-numeric suffixes, so `2.4.1-beta` evaluates correctly.

## Configuration

The engine takes no options beyond enabled; the match set is driven by the
inputs:

```yaml
engines:
  cve_watch:
    enabled: true
```

Scan inputs (illustrative):

```yaml
# ctx.data["sbom"]
sbom:
  - name: "requests"
    version: "2.28.1"

# ctx.data["cve_feed"]
cve_feed:
  - cve_id: "CVE-2026-12345"
    package: "requests"
    affected: "<2.31.0"
    cvss: 7.5
    fixed_in: "2.31.0"
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2HE1G5QDBAB3SICF7YJ7L",
  "engine": "cve_watch",
  "title": "CVE-2026-12345: requests 2.28.1 is vulnerable",
  "severity": "high",
  "score": 75.0,
  "entities": {
    "package": "requests",
    "version": "2.28.1"
  },
  "evidence": {
    "cve_id": "CVE-2026-12345",
    "cvss": 7.5,
    "affected": "<2.31.0",
    "fixed_in": "2.31.0",
    "summary": "Session fixation via crafted redirect in requests <2.31.0."
  },
  "recommendation": "Upgrade requests to 2.31.0 or later. If an upgrade is not possible, check the vendor for mitigations and monitor for exploitation attempts.",
  "tags": ["vulnerability", "dependency", "CVE-2026-12345"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
