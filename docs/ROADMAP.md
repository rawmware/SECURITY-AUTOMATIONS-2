# Roadmap — Aegis

**Aegis — Autonomous Enterprise Security Grid**
© 2026 Roman's Proposal

Current release: **2.0.0**. This roadmap is a plan, not a promise —
items move or get cut when reality intervenes.

## 2.0.x — maintenance

- Keep engine detection patterns current as attacker techniques shift.
  Rationale: a detection engine that stops updating is a false sense of
  security.
- Address bugs and false-positive reports from production deployments.
  Rationale: signal quality is the difference between a tool people use
  and a tool people mute.

## 2.1 — Scan operations

- Additional engines beyond the current 12, targeting common external
  attack surface gaps. Rationale: coverage is the core value prop.
- A scheduled-scan service with cron-style configuration. Rationale:
  recurring scans should not require an operator to run them by hand.
- A Prometheus metrics endpoint for scan results and engine health.
  Rationale: teams already running Prometheus should not need a second
  monitoring story for the monitor.

## 2.2 — Multi-user and multi-node

- A multi-node message bus so engines and pipeline stages can run on
  separate hosts. Rationale: scans and correlation should scale
  independently as finding volume grows.
- RBAC on the API. Rationale: read-only analysts and privileged
  operators should not share the same token.

## 3.0 — Distributed and verifiable

- Federated deployments: independent Aegis nodes sharing findings with
  each other across organizations. Rationale: threat signals get better
  with more eyes, without centralizing sensitive data.
- Signed evidence chains: cryptographic signatures over the
  events.jsonl trail so findings are tamper-evident end to end.
  Rationale: evidence you cannot prove is intact is just a text file.

## Non-goals

- Not an EDR, not a SIEM replacement — see THREAT-MODEL.md for scope.
- No live response actions by default, ever. The dry-run contract in
  `PlaybookRun` survives every roadmap item above.

## How roadmap items get decided

- Items land here only after someone has worked the details: which
  engine or pipeline stage changes, what new configuration it needs,
  and what tests prove it works.
- A roadmap item is not a commitment to ship it in that version.
  Shipping happens when the code, tests, and docs are all done.
- Requests and corrections from licensees are welcome and may reorder
  this list. Ideas do not.

Licensing and partnership inquiries: roman.proposal@gmail.com
