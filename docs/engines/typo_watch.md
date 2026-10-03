# typo_watch

Generates lookalike variants of the brand domain and checks which ones attackers have actually registered.

## The attack it stops

A phishing crew registers `paypa1.com` — swapping the L for a 1 — and clones
the real company's login page down to the CSS. They email customers a link
from "support@paypa1.com" with an "unusual activity" warning. A busy office
manager clicks, signs in, and hands over her password and the session cookie.
By morning the attackers are inside her account issuing refunds to stolen
cards. The phishing domain had been registered three weeks earlier.

## How detection works

`typo_watch` is a `base.Engine` subclass registered with `@register`, with
`name = "typo_watch"`. On `scan(ctx)` it reads the brand domain from
`ctx.targets["brand_domain"]` (falling back to `ctx.data["brand_domain"]`) and, if empty, returns no findings.

It generates typo-squat candidates with `generate_candidates()`, which
applies 12 squatting techniques to the brand label: omission, insertion,
adjacent-key substitution (QWERTY adjacency map), transposition, homoglyphs
(o→0, l→1, e→3, a→@, plus a full-transform pass), hyphenation, TLD swap
(co/net/org/io/dev/app), pluralization, keyword prefix/suffix (`login-`,
`secure-`, `verify-` …), vowel swaps, and letter doubling.

Each candidate (capped by `max_candidates`) is probed through the
ScanContext hooks: `dns_resolve(cand, "A")` and `dns_resolve(cand, "MX")`.
Candidates also check membership in `ctx.data["ct_log"]` — a set of domains
seen in certificate-transparency logs) and whether the brand label appears
in the candidate. Only candidates with at least one signal proceed; findings
are emitted through `self.finding()`, which clamps the score to 0–100 and derives severity from the standard bands.

## Scoring signals

Score is additive from independent signals, so stacked evidence drives
severity up:

- Resolves to an A record (+30): a web server behind the lookalike — the
  phishing page is live or about to be.
- Has MX records (+25): someone set up mail on it — phishing senders or
  inbox capture.
- Present in CT logs (+20): a TLS cert exists for it — real infrastructure, not a parked domain.
- Contains the brand keyword (+10): stronger resemblance to the real brand.

Maximum combined score is 85 (high). Any candidate under `min_score` is
dropped, so bare registrations with no A/MX/CT signal never produce noise.
A candidate that resolves **and** sits in the CT log with MX records is the
highest-confidence real threat the engine reports (85, high).

## Configuration

```yaml
engines:
  typo_watch:
    enabled: true
    max_candidates: 120   # cap on generated variants checked per scan
    min_score: 30          # drop candidates below this total score
```

`brand_domain` comes from the scan targets, not engine config:

```yaml
targets:
  brand_domain: "romansproposal.com"
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2A7M4Z8HXTW6JEBV9RC0D",
  "engine": "typo_watch",
  "title": "Lookalike domain active: romansproposa1.com",
  "severity": "high",
  "score": 85.0,
  "entities": {
    "domain": "romansproposa1.com",
    "brand": "romansproposal.com"
  },
  "evidence": {
    "candidate": "romansproposa1.com",
    "signals": {
      "a_records": ["93.184.216.34"],
      "mx_records": ["10 mail.romansproposa1.com"],
      "ct_log": true,
      "brand_keyword": true
    },
    "score_breakdown": {
      "resolves_a": 30,
      "resolves_mx": 25,
      "in_ct_log": 20,
      "brand_keyword": 10
    }
  },
  "recommendation": "Investigate romansproposa1.com: check for phishing kits or cloned login pages, file a takedown with the registrar, and consider defensively registering the variant.",
  "tags": ["typosquat", "phishing", "brand-abuse"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
