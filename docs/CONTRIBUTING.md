# Contributing to Aegis — 2.0.0

**Aegis — Autonomous Enterprise Security Grid**
© 2026 Roman's Proposal

## Proprietary software — read this first

Aegis is **proprietary software owned by Roman's Proposal**
(© 2026). It is not open source. External contributions are **not
accepted via pull request**. If you want to license Aegis, discuss
a collaboration, or propose an engine or integration, contact
**roman.proposal@gmail.com** first and describe what you have in mind.

There is no CLA to sign and no public contribution queue, because there
is no public contribution process.

## Code style

- Run **ruff** and keep it clean before any change lands.
- **Stdlib-first**: prefer the standard library over new dependencies.
  A new dependency needs a justification in writing.
- **Type hints** on all public function signatures.
- **Docstrings** on every engine, pipeline stage, and public function.
- No raw secrets in code, fixtures, logs, or evidence. Ever.

## Adding an engine — checklist

Every engine is a subclass of `aegis.engines.base.Engine`. The contract is
small and strict:

1. **Subclass `Engine`** in a new module under `aegis/engines/`.
2. **Set `name`** (snake_case, unique — e.g. `typo_watch`) and a plain
   `description` of what the engine detects.
3. **Implement `scan(ctx) -> list[Finding]`**. This is the only method you
   must write.
4. **Use only `ScanContext` I/O hooks** (`dns_resolve`, `http_get`,
   `read_file`, `now_iso`) for anything outside the process. Engines
   never do raw socket/file I/O — the hooks keep engines hermetic,
   testable, and demo-able.
5. **Emit findings via `self.finding(...)`** with a score on the **0–100**
   scale. The base class clamps and maps the score to severity using
   `severity_for_score` (≥90 critical, ≥70 high, ≥40 medium,
   ≥10 low, else informational).
6. **Register**: decorate the class with `@register` and add the module
   to the list in `load_engines()` in `aegis/engines/__init__.py`.
7. **Add a fixture** under `fixtures/` exercising the engine's detection,
   plus a doc page under `docs/` describing what it detects and how.
8. **Never log raw secrets.** If your engine touches credentials,
   tokens, or keys, redact before they reach evidence or logging —
   see `secret_sentry.py` for the pattern.

## Fixing bugs / changing the pipeline

- Pipeline stages live under `aegis/pipeline/` and run in order:
  normalize → enrich → score → correlate → dedupe → alert → respond.
- Keep the stage contract: stages wrap findings (`ScoredFinding`,
  `Case`, `Alert`, `PlaybookRun`), they don't mutate the originals.
- `PlaybookRun` defaults to `dry_run=True` — any change that weakens
  dry-run-by-default is a design change, not a bugfix, and needs review.

## Questions

roman.proposal@gmail.com
