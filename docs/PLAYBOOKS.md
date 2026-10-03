# Aegis 2.0.0 — SOAR Playbooks

Playbooks live in `aegis/soar/library/` as YAML. The respond stage matches a
qualifying `Case` to a playbook, executes it, and records a `PlaybookRun`.
`POST /soar/run` executes one on demand.

## The dry-run rule

`PlaybookRun.dry_run` defaults to `True`, and `aegis.yml`'s `dry_run`
defaults to `true`. **In dry-run mode nothing mutates the world.** Blocking
an IP, rotating a credential, filing a ticket — in dry-run these steps
execute as simulations and are recorded as such in the `steps` list, so
operators can review exactly what *would* have happened.

Live execution requires explicit approval. Approval gates sit between
analysis steps and mutation steps: a playbook may notify and gather
evidence automatically, but the step that blocks the IP or rotates the
credential pauses for a human decision. If the SOAR engine package isn't
installed, `POST /soar/run` returns a `"simulated"` `PlaybookRun` rather
than failing.

## Triggers

A playbook triggers on any combination of:

- **case severity** — e.g. run on any case with severity `high` or above
- **engine** — e.g. any finding from `canary_trip` fires immediately
- **finding tags** — e.g. findings tagged `leaked-credential` or
  `phishing-confirmed`

Triggers are declared in the playbook's `triggers:` block and evaluated by
the respond stage after correlation.

## Step types

| step | what it does |
|---|---|
| `notify` | Send an `Alert` to a channel (email, Slack, Discord, webhook) |
| `ticket` | Open or update a ticket in the tracker with the case narrative |
| `block` | Block an IP/domain at the perimeter (firewall, WAF, DNS RPZ) |
| `rotate-credential` | Revoke and reissue the compromised credential |
| `request-takedown` | File a takedown request with the registrar/host for a phishing domain |
| `escalate` | Raise to a human on-call with full case context |

## The 6 bundled playbooks

| playbook | function |
|---|---|
| `typosquat-takedown.yml` | `typo_watch` case: gather DNS/CT evidence, `request-takedown` to the registrar, `notify` the brand owner |
| `leaked-credential-rotation.yml` | `secret_sentry` finding: identify the credential owner, `rotate-credential`, `notify` with rotation confirmation |
| `brute-force-block.yml` | `auth_watch` case: confirm attack pattern, `block` the source IP, `ticket` for review |
| `phishing-site-shutdown.yml` | `phish_kit` / `url_intel` case: capture evidence, `request-takedown` to the host, `block` the domain |
| `tls-expiry-escalation.yml` | `tls_watch` finding: warn while the cert still has runway, `escalate` as expiry approaches, `ticket` the renewal |
| `canary-trip-response.yml` | `canary_trip` finding: treat as active intrusion — `notify` on-call immediately, open an incident `ticket`, freeze scope for investigation |

## Playbook schema

```yaml
# aegis/soar/library/brute-force-block.yml
name: brute-force-block
description: Block brute-force sources after pattern confirmation.
version: "1.0.0"

triggers:
  engines: [auth_watch]
  min_severity: high
  tags: [brute-force]

steps:
  - name: confirm-pattern
    action: notify
    channel: slack
    target: "#security"
    message: "Brute-force pattern confirmed on {{ case.entities.ip }}"

  - name: block-source
    action: block
    target: "{{ case.entities.ip }}"
    approval: required        # gate: human approves before the block

  - name: open-ticket
    action: ticket
    title: "Blocked brute-force source {{ case.entities.ip }}"

on_complete:
  case_status: contained
```

Fields: `name`, `description`, `version`, `triggers` (engines / min_severity /
tags), `steps` (ordered; each with `action` and action-specific params),
`approval: required` on any step that mutates the world, and `on_complete`
for case status updates. Steps are recorded in order on the `PlaybookRun`
with their outcome, so every run is a full audit trail.
