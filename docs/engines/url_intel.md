# url_intel

Unshortens URLs, follows redirect chains, and scores links for phishing indicators before anyone clicks them.

## The attack it stops

The office manager of a dental practice gets an email that looks like a
shipment notification from a known supplier: a `bit.ly` link to "track
your package." She clicks on her work laptop. The shortener bounces through two redirects
and lands on a credential-harvesting page styled to match the supplier.
She "signs in"; the attackers capture her email password — reused for the
practice's billing portal — and two weeks later they're pulling patient
records. One link nobody inspected.

## How detection works

`url_intel` is a `base.Engine` subclass registered with `@register`,
`name = "url_intel"`. On `scan(ctx)` it reads the URLs to evaluate from
`ctx.data["urls"]`. For each URL it calls `ctx.http_get(url)` — the
ScanContext HTTP hook — and takes `response["redirects"]` as the followed
redirect chain, with the final hop as the effective destination. All network
I/O goes through that hook; the engine never fetches anything itself.

The URL (plus its chain) is scored by `_score_url()` with a transparent,
additive heuristic breakdown: punycode/IDN hosts, IP-literal hosts,
`@`-injection in the netloc, shady TLDs, overlong query strings, phishing
keywords in the URL, redirect-chain depth, and excessive total length. The
score is capped at 100 and anything at or above `min_score` becomes a finding via `self.finding()`, with the full breakdown in the evidence.

## Scoring signals

Individual heuristic weights (capped total 100):

- IP-literal host (+30): `https://203.0.113.77/login` — legitimate sites
  don't make users log into bare IPs.
- Punycode/IDN host `xn--` (+25): internationalized-domain lookalike trick.
- `@` in the netloc (+20): `https://real.com@evil.top` — the browser goes to whatever follows the `@`.
- Shady TLD (+15): `.top`, `.xyz`, `.click`, `.zip`, `.mov`, `.country`.
- Redirect chain of 2+ hops (+15): shortener masking the real destination.
- Phishing keywords (+10 each, max 20): login, verify, wallet, invoice, urgent in the URL.
- Query longer than 120 chars (+10): token stuffing / redirect payloads.
- Total length over 200 chars (+10): obfuscation by bloat.

Anything scoring ≥ `min_score` (default 40, medium) is flagged. A URL that
stacks punycode + keywords + a redirect chain clears 70 (high) fast; a lone
long query string at 10 stays quiet.

## Configuration

```yaml
engines:
  url_intel:
    enabled: true
    min_score: 40   # flag URLs scoring at or above this threshold
```

URLs to evaluate are supplied with the scan:

```yaml
# scan input shape (illustrative)
urls:
  - "https://bit.ly/3xQ9zWm"
  - "https://xn--secur3-login.top/verify"
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2FC9E3OBZYZ1QGAD5WH5J",
  "engine": "url_intel",
  "title": "Suspicious URL: https://bit.ly/3xQ9zWm",
  "severity": "medium",
  "score": 60.0,
  "entities": {
    "url": "https://bit.ly/3xQ9zWm",
    "host": "bit.ly",
    "final_url": "https://secure-login-update.top/invoice"
  },
  "evidence": {
    "url": "https://bit.ly/3xQ9zWm",
    "final_url": "https://secure-login-update.top/invoice",
    "redirects": [
      "https://short.redirect.io/a1",
      "https://secure-login-update.top/invoice"
    ],
    "redirect_hops": 2,
    "score_breakdown": {
      "shady_tld": 15,
      "redirect_chain": 15,
      "phish_keywords": 20,
      "long_query": 10
    }
  },
  "recommendation": "Do not click. Quarantine the message, verify the sender through a separate channel, and submit the URL to the phishing triage queue.",
  "tags": ["phishing", "url-intel", "initial-access"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
