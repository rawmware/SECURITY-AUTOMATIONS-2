# Aegis 2.0.0 — Architecture

Aegis ("Autonomous Enterprise Security Grid") is a twelve-engine defensive
security automation platform. It detects, scores, correlates, and responds —
keeping humans out of the loop for the boring parts, and squarely in the loop
for the dangerous ones.

Proprietary software © 2026 Roman's Proposal.

## System diagram

```
                    +---------------------+
                    |  aegis/config.py    |
                    |  aegis.yml (toggles,|------> ScanRunner, engines, SOAR
                    |  thresholds, options)|
                    +----------+----------+
                               |
   +--------------+ +---------+---------+ +--------------+
   | typo_watch   | | dns_sentinel      | | tls_watch    |
   | port_watch   | | auth_watch        | | url_intel    |
   | secret_sentry| | cve_watch         | | cloud_posture|
   | phish_kit    | | anomaly_mind      | | canary_trip  |
   | (aegis/engines/)                   |              |
   +------+-----------------------------+--------------+
          | scan(ctx) -> list[Finding]
          v
   +-------------------+       pub/sub       +-----------------+
   | ScanRunner        |  ----> bus: Bus ----> | WebSocket       |
   | (aegis/runner.py) |       topics:        | /stream         |
   |   per-engine      |       "findings",    | (live findings) |
   |   isolation       |       "cases"        +-----------------+
   +---------+---------+
             | list[Finding]
             v
   +-------------------------------+
   | Pipeline (aegis/pipeline/)    |
   |  normalize -> enrich -> score |
   |  -> correlate -> dedupe       |
   +-------------------------------+
             | list[ScoredFinding] / list[Case]
             v
   +----------------+       +-------------------+
   | alert stage    |------>| Alert -> channels  |
   | (>= alert_     |       | (Email, Slack,     |
   |  threshold)    |       |  Discord, webhook) |
   +----------------+       +-------------------+
             |
             v  (Case with severity >= threshold)
   +-------------------+
   | SOAR respond stage|
   | YAML playbooks in |
   | aegis/soar/       |
   | library/, dry-run |
   | by default        |
   +---------+---------+
             v
   +-------------------+      +-----------------+
   | PlaybookRun record|      | API + web UI    |
   | (audit trail)     |      | aegis/api/,     |
   +-------------------+      | aegis-build/web/|
                              +-----------------+
```

## Component responsibilities

| Component | Location | Responsibility |
|---|---|---|
| Engines | `aegis/engines/` | Detection only. Each implements `scan(ctx) -> list[Finding]`. No raw I/O; everything goes through the injected `ScanContext`. |
| ScanRunner | `aegis/runner.py` | Loads registered engines, builds a `ScanContext` per scan, runs every enabled engine in isolation (one bad engine never kills a scan), pushes findings through the pipeline. |
| Bus | `aegis/bus.py` | Lightweight synchronous pub/sub (`subscribe` / `publish` / `topics`). The websocket stream subscribes to `findings`; alerting subscribes to the same events. |
| Pipeline | `aegis/pipeline/` | Seven stages (see `PIPELINE.md`). Pure-ish functions over the models; stages wrap findings rather than mutating them in place. |
| Models | `aegis/models.py` | `Finding`, `ScoredFinding`, `Case`, `Alert`, `PlaybookRun`. Plain dataclasses with `to_dict()` for JSON output. |
| Config | `aegis/config.py` | `AegisConfig`: `brand_domain`, `alert_threshold` (default 40.0), `dry_run` (default True), `state_dir` (default `"state"`), per-engine options and `enabled` flags. |
| SOAR | `aegis/soar/library/` | YAML playbooks executed against cases/findings; dry-run by default. |
| API | `aegis/api/` | FastAPI surface: health, engines, scans, findings, cases, alerts, SOAR runs, websocket stream. |
| Web UI | `aegis-build/web/` | Dashboard built on the API and `/stream` websocket. |

## Data flow

1. **scan**: `POST /scan` (or the CLI) hands targets to `ScanRunner`, which
   runs each enabled engine's `scan(ctx)` and collects raw `Finding` objects.
2. **finding**: pipeline normalizes and enriches each finding, then the
   scoring stage produces a `ScoredFinding` (adjusted score + factors +
   re-derived severity).
3. **case**: correlation groups scored findings sharing entities (domains,
   IPs, time windows) into a `Case` — an attack chain with a narrative.
4. **playbook**: a case at or above the alert threshold triggers the respond
   stage, which executes the matching YAML playbook as a `PlaybookRun`
   (dry-run unless explicitly approved for live actions).

## Design decisions

- **Stdlib-first engines.** Engines use the Python standard library plus
  injected I/O. No sprawling dependency trees to audit or break.
- **Injected I/O (`ScanContext`).** Engines never touch sockets, files, or
  the clock directly — they call `ctx.dns_resolve`, `ctx.http_get`,
  `ctx.read_file`, `ctx.now_iso`, or read scenario data from `ctx.data`.
  This makes tests hermetic and lets the demo simulate the entire internet.
- **Dry-run-by-default SOAR.** `PlaybookRun.dry_run` defaults to `True` and
  the config's `dry_run` defaults to `True`. Nothing mutates the world until
  a human approves live execution.
- **Immutable-ish findings through the pipeline.** Stages take a `Finding`
  and return a new object (`ScoredFinding` wraps rather than edits). The
  evidence trail is never overwritten, so every score can be traced back
  to the engine's original output.
- **Defensive assembly.** The runner and API import pipeline stages and the
  SOAR engine defensively; if a package isn't built yet, documented identity
  fallbacks keep the system functional (e.g. `/soar/run` returns a
  `"simulated"` `PlaybookRun` rather than a 500).
- **Known wiring gap: per-engine options vs `ctx.options`.** Two option
  paths exist and they are not yet merged. Engines that read
  `self.opt(...)` (typo_watch, auth_watch, url_intel) receive their
  `aegis.yml` `engines:<id>:` section via the constructor, so those options
  work. Engines that read `ctx.option(...)` (anomaly_mind's
  `alpha`/`window`/`threshold`, phish_kit's `min_score`, secret_sentry's
  `allowlist`) do *not* see config-file values, because `ScanRunner`
  builds `ScanContext` without `options=` — only tests and the demo, which
  inject options directly, can tune them today. The fix is a one-liner in
  `ScanRunner.build_context` (merge `config.engine_options(name)` into
  `ctx.options`); it is flagged for the runner owner, not worked around
  here.
