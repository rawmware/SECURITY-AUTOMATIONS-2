# dns_sentinel

Diffs live DNS answers against a known-good baseline to catch hijacks, reroutes, and takeover signals.

## The attack it stops

An attacker compromises the registrar account of a small accounting firm
through a reused password. They change the A record for `mail.` and the MX
records for the whole domain to point at their own relay. Incoming invoices
and tax documents now land in the attacker's inbox, which silently forwards
a copy on so nothing looks broken. Over six weeks they harvest W-2s and
bank letters from a dozen clients, then use them for fraudulent tax refunds.
The firm only learns of it when a client asks why their accountant replied
from a strange server. DNS stayed "working" the entire time — it was just
working for someone else.

## How detection works

`dns_sentinel` is a `base.Engine` subclass registered with `@register`,
`name = "dns_sentinel"`. On `scan(ctx)` it reads the watched hostnames from
`ctx.targets["dns_hosts"]` and the known-good baseline from
`ctx.data["dns_baseline"]` — a mapping of `host -> {rtype: [values]}`.

For each host, if no baseline entry exists and any record type resolves, it
emits a single "new host outside baseline" finding (a possible shadow-IT
asset or attacker subdomain). Otherwise it queries `ctx.dns_resolve(host,
rtype)` for each of A, AAAA, MX, TXT, NS and set-diffs the current answers
against the baseline, reporting exactly which values were added and which
were removed in the finding evidence. The engine performs no raw socket I/O
— all DNS goes through the ScanContext hook — and each finding is built
with `self.finding()`, which clamps the score and derives severity from the
standard bands.

## Scoring signals

Score is fixed per record type, reflecting blast radius rather than a
computed sum:

- NS or MX changed (80, high): authority or mail flow moved — the strongest
  hijack signal. Losing control of MX means every inbound email is gone.
- A or AAAA changed (55, medium): web traffic rerouted. Legitimate for
  migrations, which is why the recommendation asks for authorization
  confirmation rather than assuming compromise.
- TXT changed (30, low): SPF/DKIM tokens or verification records altered —
  often benign (rotated SPF), but attackers change these to legitimize
  spoofed mail.
- Host with no baseline entry but resolvable records (55, medium): unknown
  asset — could be a new legitimate service or a claimed dangling subdomain.

Drift in the *wrong direction* (records reverted toward baseline) scores
identically; any unauthorized change is the signal.

## Configuration

Record types are fixed at A / AAAA / MX / TXT / NS in the module. What you
configure is the watch list and the baseline:

```yaml
engines:
  dns_sentinel:
    enabled: true

targets:
  dns_hosts:
    - "romansproposal.com"
    - "mail.romansproposal.com"
    - "www.romansproposal.com"
```

The baseline (`ctx.data["dns_baseline"]`) is maintained by the operator and
supplied with the scan — update it after every *authorized* DNS change so
real drift stands out.

## Sample finding

```json
{
  "id": "fnd_01K9Q2B8N5A9KXUV7LCWZ1SD1E",
  "engine": "dns_sentinel",
  "title": "DNS drift on mail.romansproposal.com (MX records changed)",
  "severity": "high",
  "score": 80.0,
  "entities": {
    "host": "mail.romansproposal.com",
    "rtype": "MX"
  },
  "evidence": {
    "host": "mail.romansproposal.com",
    "rtype": "MX",
    "added": ["10 mx.attacker-relay.net"],
    "removed": ["10 mx.google.com"],
    "baseline": ["10 mx.google.com"],
    "current": ["10 mx.attacker-relay.net"]
  },
  "recommendation": "MX records for mail.romansproposal.com changed outside the baseline. Confirm the change was authorized; if not, treat as a possible DNS hijack and rotate registrar credentials.",
  "tags": ["dns", "baseline-drift", "mx"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
