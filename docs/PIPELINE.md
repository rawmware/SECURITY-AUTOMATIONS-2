# Aegis 2.0.0 — Pipeline

Seven stages, in order. Each stage is a pure-ish function over the models in
`aegis/models.py`. Implementations live in `aegis/pipeline/` (`normalize.py`,
`enrich.py`, `score.py`, and the correlate/dedupe/alert/respond stages
alongside them). The runner (`aegis/runner.py`) imports stages defensively —
if a stage isn't built yet, a documented identity fallback keeps scans
working.

```
normalize -> enrich -> score -> correlate -> dedupe -> alert -> respond
```

## 1. normalize

**What it does:** takes each raw `Finding` from an engine and puts it into
canonical shape — consistent entity keys, trimmed strings, valid severity
(unknown severities raise `ValueError`; this stage refuses to pass them
through), clamped scores.

**Input:** `Finding` (raw, per engine). **Output:** `Finding` (canonical).

## 2. enrich

**What it does:** adds context the engine didn't have — asset criticality
from the inventory, geolocation of IPs, reverse DNS, whois age for domains,
whether an entity is on a watchlist. Enrichment never changes the score;
it only adds facts to `evidence` and `entities` for later stages to use.

**Input:** `Finding`. **Output:** `Finding` (enriched).

## 3. score

**What it does:** converts the engine's raw score into an operational one.

```
adjusted_score = base score adjusted by asset criticality,
                 confidence, and business context
```

Every adjustment is recorded in the `factors` dict — e.g.
`{"asset_criticality": +15, "confidence": -5, "business_context": 0}` — so
anyone can see exactly why the score moved. The adjusted severity is then
re-derived from the fixed `severity_for_score` bands (≥90 critical, ≥70
high, ≥40 medium, ≥10 low, else informational).

**Input:** `Finding` (enriched). **Output:** `ScoredFinding` — wraps the
original finding and adds `adjusted_score`, `adjusted_severity`, and the
`factors` dict. `to_dict()` adds `adjusted_score`, `adjusted_severity`,
and `score_factors` to the standard finding keys.

This stage is described at the contract level here on purpose: the exact
weighting logic lives in `aegis/pipeline/score.py`. The contract is that
no adjustment is ever silent — it shows up in `factors`, or it didn't
happen.

## 4. correlate

**What it does:** groups findings that share entities — domains, IPs, time
windows — into a `Case`: a correlated attack campaign with a `narrative`.
Attack chains, not alert piles.

A `typo_watch` finding about `examp1e.com`, a `url_intel` finding scoring a
phishing URL on that domain, and a `phish_kit` finding fingerprinting the
page behind it are one campaign, not three alerts. The correlator builds
that `Case`, picks the campaign severity from the strongest finding
(re-derived through the severity bands), and writes a plain-language
narrative: what happened, in what order, touching which entities.

**Input:** `list[ScoredFinding]`. **Output:** `list[Case]` — each with
`title`, `findings`, `severity`, `score`, `entities`, `narrative`,
`status` (default `"open"`), `id`, `ts`.

## 5. dedupe

**What it does:** fingerprint-based suppression. Each finding gets a stable
fingerprint (engine + normalized title + entity signature); findings whose
fingerprint matches an already-open case or a recently processed finding
are suppressed instead of re-alerted. The same brute-force burst doesn't
page you forty times — it lands in the existing case once.

**Input:** `list[Case]` (plus the recent-finding store in `state/`).
**Output:** `list[Case]` (new or materially changed), suppressed items
logged for audit.

## 6. alert

**What it does:** decides what reaches a human. Anything with an adjusted
score at or above `alert_threshold` (default `40.0` in `aegis.yml`) becomes
an `Alert`: `target`, `channel`, `subject`, `body`, `severity`,
`delivered=False`. Channels include email, Slack, Discord, and webhooks;
delivery marks `delivered=True` or leaves it `False` with the failure
recorded.

**Input:** `list[Case]`. **Output:** `list[Alert]`.

## 7. respond

**What it does:** hands qualifying cases to the SOAR layer. A case at or
above the response threshold executes the matching YAML playbook from
`aegis/soar/library/` and records a `PlaybookRun` — `playbook`, `trigger`,
`steps`, `dry_run` (default `True`), `status` (default `"completed"`),
`id`, `ts`. See `PLAYBOOKS.md` for the full SOAR design.

**Input:** `Case` (qualifying). **Output:** `PlaybookRun` (audit trail).

## Through-line

Findings are immutable-ish across stages: each stage wraps or transforms
into a new object rather than editing the last one. `ScoredFinding`
preserves the original `Finding` verbatim inside `to_dict()` — the
evidence an engine produced is never overwritten by the pipeline's opinion
about it.
