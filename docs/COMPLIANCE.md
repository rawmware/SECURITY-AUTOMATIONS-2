# Compliance Mapping — Aegis 2.0.0

**Aegis — Autonomous Enterprise Security Grid**
© 2026 Roman's Proposal (proprietary)

This document maps Aegis 2.0.0 capabilities to the NIST Cybersecurity
Framework (CSF) 2.0 functions and to the SOC 2 trust service criteria.
It uses "assists with" language throughout because that is what is true:
**Aegis is not certified against NIST CSF or SOC 2, and deploying Aegis
does not confer certification or compliance status on its own.**
Compliance is a property of an organization, its processes, and its
audits — not of a single tool.

## NIST CSF 2.0 mapping

CSF 2.0 functions: Govern (GV), Identify (ID), Protect (PR),
Detect (DE), Respond (RS), Recover (RC).

| Engine / pipeline stage | CSF function | Assists with |
|---|---|---|
| typo_watch | Detect (DE) | Detecting lookalike-domain registration used in brand phishing |
| dns_sentinel | Detect (DE) | Detecting DNS drift/hijack signals against a known baseline |
| tls_watch | Protect (PR) | Monitoring certificate expiry and TLS misconfiguration |
| port_watch | Identify (ID) | Maintaining an inventory of exposed attack surface |
| auth_watch | Detect (DE) | Detecting brute-force and credential-spray auth anomalies |
| url_intel | Detect (DE) | Assessing suspicious URLs before user interaction |
| secret_sentry | Protect (PR) | Identifying leaked credentials in code/configs/logs |
| cve_watch | Identify (ID) | Identifying known vulnerabilities in deployed inventory |
| cloud_posture | Identify (ID), Protect (PR) | Identifying cloud misconfigurations that weaken protection |
| phish_kit | Detect (DE) | Detecting phishing-kit indicators targeting the organization |
| anomaly_mind | Detect (DE) | Detecting statistical anomalies across collected signals |
| canary_trip | Detect (DE) | Detecting intrusion via canary tokens and tripwires |
| normalize → enrich → score | Detect (DE) | Giving every detection consistent context and a severity label |
| correlate → dedupe | Detect (DE) | Reducing alert fatigue so real incidents get attention |
| alert | Respond (RS) | Routing confirmed signals to the right humans/systems |
| respond (dry-run SOAR) | Respond (RS) | Preparing response actions with human-visible playbooks |
| events.jsonl / per-run reports | Govern (GV) | Providing evidence trails that governance processes can audit |
| recover | Recover (RC) | **Not covered.** Aegis has no recovery-orchestration function |

## SOC 2 trust criteria mapping

| Aegis capability | SOC 2 criterion | Assists with |
|---|---|---|
| Engine scans, scored findings, deduped alerts | Security (CC7) | Ongoing monitoring of the attack surface |
| alert routing + response playbooks | Security (CC7.3) | Structured incident response workflow support |
| secret_sentry (redaction before evidence) | Confidentiality | Handling leaked secrets without spreading them further |
| tls_watch, cloud_posture | Security (CC6) | Configuration hardening signals |
| events.jsonl evidence trail | Security (CC8) | Change/audit evidence that auditors may consume |
| availability monitoring of services | Availability | **Limited.** port_watch can see a service drop; Aegis is not an APM |

## What this mapping is not

- Not a certification claim. Aegis has not been assessed against NIST CSF
  or SOC 2 by any auditor.
- Not legal or audit advice. Your auditor decides what counts as evidence
  for your control environment.
- Not a promise of coverage: engines produce signals; controls need
  people, process, and review around them.

Questions about licensing or formal assessment support:
roman.proposal@gmail.com
