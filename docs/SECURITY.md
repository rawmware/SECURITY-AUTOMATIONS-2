# Security Policy — Aegis 2.0.0

**Aegis — Autonomous Enterprise Security Grid**
© 2026 Roman's Proposal

## Responsible disclosure

Found a vulnerability in Aegis? Report it to
**roman.proposal@gmail.com** with the subject line
`Aegis security report`.

**What to include:**

- Aegis version (see `aegis/version.py`) and how you deployed it
  (Docker, k8s, bare Python).
- A plain description of the vulnerability and its likely impact.
- Steps to reproduce, or a minimal proof of concept.
- Your contact details and whether you want credit.

**What NOT to send:**

- Do not send raw secrets, customer data, or production credentials —
  even to demonstrate the issue. Redact them.
- Do not exploit the issue against anyone's deployment but your own.
- Do not disclose publicly before we have had a reasonable chance
  to fix it.

We will acknowledge receipt and keep you updated on the fix.

## Safety properties

### Dry-run-by-default SOAR

The `respond` pipeline stage and all `PlaybookRun` objects default to
**`dry_run=True`**. Playbooks describe actions; they do not execute live
mutations (block an IP, revoke a key, push a firewall rule) unless an
operator **explicitly opts in** per run. There is no global "live mode"
switch to flip by accident.

### Secrets handling

- Engines must **redact secrets before they reach evidence or logging**.
  Findings carry redacted previews only (see `secret_sentry.py`).
- Configuration containing secrets (API keys, webhook tokens) is
  provided via **environment variables**, never committed to the repo
  or baked into images.
- Test fixtures must not contain real credentials — only synthetic ones
  that no system would accept.

### Supply chain

- Minimal dependency surface: `fastapi`, `uvicorn`, `pyyaml`, and the
  stdlib. A new dependency needs a written justification (see
  CONTRIBUTING.md).
- Base Docker image is pinned by digest, not by floating tag.
- CI runs the full hermetic test suite (`pytest`) and `ruff` on every
  change to `main`.

## Scope limits

This policy covers Aegis 2.0.0 as shipped by Roman's Proposal. It does
not cover third-party integrations you wire into Aegis, the security of
your own hosting infrastructure, or vulnerabilities in upstream
dependencies themselves (report those upstream, then tell us).

## Contact

Security reports and licensing questions: roman.proposal@gmail.com
