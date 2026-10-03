# Web Demo — Aegis 2.0.0

**Aegis — Autonomous Enterprise Security Grid**
© 2026 Roman's Proposal

## Status: scaffolding only

`web/` currently contains only empty `js/`, `css/`, and `assets/`
directories — no demo files are staged yet. This page documents the
intended design of the demo and how it maps to the real codebase, so
whoever builds it gets the mapping right from the start.

## How the demo maps to real code

| Demo piece | Maps to | How |
|---|---|---|
| `web/js/sim.js` | `aegis/models.py` — `severity_for_score`, `SCORE_BANDS` | Must mirror the exact bands: ≥90 critical, ≥70 high, ≥40 medium, ≥10 low, else informational. Finding scores are clamped 0–100 on both sides. |
| Demo scenarios | The 12 engines under `aegis/engines/` | Each scenario mirrors one engine's detection logic: `typo_watch`, `dns_sentinel`, `tls_watch`, `port_watch`, `auth_watch`, `url_intel`, `secret_sentry`, `cve_watch`, `cloud_posture`, `phish_kit`, `anomaly_mind`, `canary_trip`. |
| `web/js/scene3d.js` | Pipeline models: `Finding`, `ScoredFinding`, `Case` | Visualizes findings and the correlated cases the pipeline produces. |
| Playbook preview | `PlaybookRun(dry_run=True)` | Shows what the SOAR layer *would* do — never executes. |

## Where the demo simulates

The seam is `ScanContext`. Real engines never touch raw sockets or the
filesystem — every I/O call goes through the injected hooks
(`dns_resolve`, `http_get`, `read_file`, `now_iso`). In tests these are
stubbed; in the demo they are stubbed too, with canned scenario data.
The engine `scan()` methods run unchanged against simulated DNS/HTTP.
This is by design: the same isolation that keeps tests hermetic is what
makes the demo honest about what it is.

## What's real

- The **severity bands** (90/70/40/10) are the actual algorithm from
  `aegis/models.py`, not a visual approximation.
- The **finding schema** (`engine`, `title`, `severity`, `score`,
  `entities`, `evidence`, `recommendation`, `tags`) is the real one.
- The **correlation concept** (normalize → enrich → score → correlate →
  dedupe → alert → respond) is the actual pipeline order from
  `aegis/pipeline/`.
- The **playbook dry-run logic** is real: `dry_run=True` is the default
  in the backend, and the demo must reflect that.

## What's simulated

- All network I/O (DNS answers, HTTP responses, log lines) is canned
  scenario data fed through the `ScanContext` hooks.
- Timing is compressed for presentation; a real scan takes as long as
  the hooks take.
- No actual remediation happens — the demo shows playbook steps in
  dry-run mode only.

## Building it

Keep the demo honest: any divergence between `sim.js` severity labels
and `severity_for_score` is a bug, not a design choice. Scenario authors
should write each scenario against the corresponding engine module's
docstring so the demo's description matches the real detection logic.

Questions: roman.proposal@gmail.com
