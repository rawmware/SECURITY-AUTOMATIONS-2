# Threat Model — Aegis 2.0.0

**Aegis — Autonomous Enterprise Security Grid**
© 2026 Roman's Proposal

A threat model is a statement of assumptions. If an assumption here
does not match your situation, Aegis may not protect you the way you
expect. Read this before deploying.

## What Aegis assumes about the attacker

Aegis is built to catch an **external attacker** with ordinary
capabilities — internet access, commodity tooling, and time. Specifically:

- **Typosquatting** — registering lookalike domains to phish your users
  (`typo_watch`).
- **DNS hijack / drift** — subverting name resolution to redirect traffic
  (`dns_sentinel`).
- **Credential stuffing and password spraying** — throwing leaked or
  common credentials at auth endpoints (`auth_watch`).
- **Leaked secrets** — finding API keys, tokens, and private keys in
  code, configs, and logs before an attacker does (`secret_sentry`).
- **Phishing kits** — reusing known kit infrastructure against your
  brand (`phish_kit`).
- **Vulnerability exploitation** — using known CVEs against exposed
  services (`cve_watch`).
- **Cloud misconfiguration** — walking through doors left open by
  over-permissive IAM, public buckets, and exposed consoles
  (`cloud_posture`).

## What Aegis does NOT cover

Stated plainly, because a security tool that overpromises is worse
than none at all:

- **Insider threat.** An attacker with legitimate credentials and normal
  access patterns has limited visibility in Aegis. Detecting malicious
  insiders requires behavioral baselining Aegis does not attempt.
- **Zero-days.** By definition, unknown vulnerabilities have no signature
  and no inventory record for `cve_watch` to match.
- **Physical access.** If someone can walk up to the hardware, this is
  the wrong layer of defense.
- **Supply-chain compromise of dependencies.** Aegis pins its base image
  and keeps dependencies minimal (fastapi/uvicorn/pyyaml), but a
  compromised upstream package is outside its detection scope.
- **Encrypted-traffic content inspection.** Aegis does not MITM or
  decrypt TLS; it watches metadata, configuration, and signals.

## Scope boundaries

- Aegis monitors **external attack surface and credential/auth signals**.
- Aegis is **not an EDR**: it does not run on endpoints or inspect
  processes.
- Aegis is **not a SIEM replacement**: it produces findings and cases,
  not a general-purpose log platform. Findings feed into your SIEM via
  `events.jsonl`; they do not replace it.

## Assumptions the deployment must hold up

- The `ScanContext` hooks in production point at real data. If your
  DNS/HTTP/file inputs are stale or filtered, findings are stale too.
- Playbook dry-run defaults are left alone. Disabling dry-run turns
  Aegis into a loaded tool — your responsibility, your audit trail.
- Secrets stay in environment configuration, never in code or fixtures.

Questions about scope or licensing: roman.proposal@gmail.com
