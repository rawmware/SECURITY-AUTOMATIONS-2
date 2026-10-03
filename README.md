# AEGIS — Autonomous Enterprise Security Grid

**Twelve detection engines. One pipeline. Automatic response.**

Aegis watches your domains, logins, cloud, and code around the clock. When something's wrong, it doesn't just alert — it scores the finding, stitches related findings into a single case, and runs a response playbook. The boring parts of security operations happen without a human in the loop.

🎛️ **[Try the live interactive demo](https://rawmware.github.io/SECURITY-AUTOMATIONS-2/)** — run simulated attacks against a 3D operations view and watch all twelve engines detect, correlate, and respond in real time. No signup, no install.

> **Proprietary software.** © 2026 Roman's Proposal. Source is visible for evaluation; commercial use, redistribution, or production deployment requires a written license. See [PROPRIETARY-LICENSE.md](PROPRIETARY-LICENSE.md).

---

## Why this exists

Every internet-connected system is probed thousands of times a day by automated scanners. A firewall sees the noise; a human reviews a sliver of it. The gap between "probes seen" and "probes reviewed" is where breaches live.

Aegis closes that gap the only way that scales: software that watches, decides, and acts — and only wakes a human when judgment is actually required.

## The twelve engines

| Engine | What it catches |
|---|---|
| `typo_watch` | Lookalike domains impersonating your brand (12 generation techniques + DNS/MX/CT scoring) |
| `dns_sentinel` | DNS record drift — hijacks and unauthorized changes vs. a known-good baseline |
| `tls_watch` | Expiring certificates, weak signature algorithms, short keys, SAN mismatches |
| `port_watch` | Unexpected open ports — attack-surface drift vs. expected host profiles |
| `auth_watch` | Brute-force, password spraying, and distributed login attacks from auth logs |
| `url_intel` | Malicious links — unshortening + heuristic threat scoring |
| `secret_sentry` | Leaked credentials in code and text (entropy-gated, never logs raw secrets) |
| `cve_watch` | Known vulnerabilities in your dependencies (SBOM × CVE feed matching) |
| `cloud_posture` | Cloud misconfigurations — public buckets, open security groups, wildcard IAM |
| `phish_kit` | Phishing-kit fingerprints in web pages (Telegram exfil, harvesters, obfuscation) |
| `anomaly_mind` | Statistical anomalies in event rates (EWMA + z-score, impossible-travel heuristics) |
| `canary_trip` | Honeytoken tripwires — fake credentials that only an attacker would touch |

Each engine is a pure `scan(ctx) -> list[Finding]` function. All I/O (DNS, HTTP, files) is injected through `ScanContext` hooks, so every engine is hermetically testable and the demo can simulate the internet.

## The pipeline

A finding is not an alert. Raw findings pass through seven stages before anyone's phone buzzes:

```
normalize → enrich → score → correlate → dedupe → alert → respond
```

1. **Normalize** — telemetry coerced into a common shape.
2. **Enrich** — asset criticality attached (a probe against the payments DB outranks one against a dev blog).
3. **Score** — 0–100 risk score adjusted for criticality and confidence; severity bands at 90/70/40/10.
4. **Correlate** — findings sharing an entity inside a time window are stitched into one **case**: an attack chain with a plain-English narrative, not a pile of alerts.
5. **Dedupe** — repeats suppressed by fingerprint within a time window.
6. **Alert** — only cases above your threshold route to Slack/Discord/email/webhook.
7. **Respond** — a SOAR playbook executes: block the IP, revoke the token, open the ticket. **Dry-run by default** — nothing acts on your infrastructure until you say so.

## SOAR playbooks

Six response playbooks ship in `aegis/soar/library/`, each a readable YAML: trigger conditions, ordered steps, and approval gates for destructive actions. The playbook engine templates parameters from case entities (`block_ip: {src_ip}`) and keeps a full audit log of every action taken — or *would-have-taken* in dry-run mode.

## Run it

```bash
pip install aegis-security        # (or: pip install -e .)
cp aegis.example.yml aegis.yml    # tune targets + thresholds

aegis engines                     # list the fleet
aegis scan --config aegis.yml --out findings.json
aegis serve --port 8000           # REST API + live finding websocket
```

Or with Docker:

```bash
docker compose up
# API at http://localhost:8000 — try POST /scan
```

API reference: [docs/API.md](docs/API.md). Deployment (k8s, scheduling): [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## The demo is honest about what's simulated

The [web demo](https://rawmware.github.io/SECURITY-AUTOMATIONS-2/) runs entirely in your browser. Its `sim.js` mirrors the real Python scoring bands, correlation, and dedupe semantics — but DNS lookups, HTTP fetches, and log tails are simulated scenario data, not live telemetry. [docs/DEMO.md](docs/DEMO.md) documents exactly where the simulation ends and the real platform begins. Engineers: the Python in `aegis/` is the source of truth.

## Repo layout

```
aegis/
  engines/        12 detection engines (stdlib-only)
  pipeline/       normalize → enrich → score → correlate → dedupe → alert
  soar/           playbook engine, actions, library/*.yml
  api/            FastAPI: REST + /stream websocket
  cli.py          aegis CLI
web/              interactive demo (static, GitHub Pages)
docs/             architecture, per-engine deep dives, compliance mapping
k8s/              Kubernetes manifests
```

## Compliance posture

Aegis **assists with** — not certifies — common frameworks. [docs/COMPLIANCE.md](docs/COMPLIANCE.md) maps engines and pipeline stages to NIST CSF 2.0 functions and SOC 2 trust services criteria, in honest "assists with" language.

## License

Proprietary — © 2026 Roman's Proposal. Evaluation and security research use permitted; commercial licensing: roman.proposal@gmail.com. See [PROPRIETARY-LICENSE.md](PROPRIETARY-LICENSE.md).
