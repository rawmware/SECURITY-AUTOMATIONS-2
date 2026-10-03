# tls_watch

Scores TLS certificates on expiry, signature algorithm, key size, and hostname coverage.

## The attack it stops

A nonprofit's donation site has its certificate expire on a Friday night.
By Saturday morning every donor's browser shows a full-page red warning:
"Your connection is not private." Donations stop cold for the 48 hours it
takes a volunteer to figure out how renewal works — and in the donation
season that weekend was worth thousands. Worse, a smaller slice of visitors
clicks through the warning anyway, training them to ignore the exact
warning that protects them. An expired cert is also the window where an
attacker with a forged SHA-1 collision can slip an interception proxy
between users and the site while everyone assumes the error is "just the
cert being expired again."

## How detection works

`tls_watch` is a `base.Engine` subclass registered with `@register`,
`name = "tls_watch"`. On `scan(ctx)` it reads certificate records from
`ctx.data["tls_certs"]` — a list of dicts with `host`, `not_after` (ISO
date), `sig_alg`, `key_bits`, and `san_ok` — supplied by whatever TLS
metadata collection feeds the scan (expiry dates derived from `http_get` /
TLS metadata upstream). It compares `not_after` against `ctx.now_iso()` and
evaluates each certificate independently against four rules:

1. Expiry: <14 days, <30 days, <60 days remaining → separate findings.
2. Weak signature algorithm: `sig_alg` containing `sha1` or `md5` → finding.
3. Undersized key: `key_bits < 2048` → finding.
4. Hostname coverage: `san_ok` false → finding.

Each rule fires independently — one certificate can yield multiple findings. All findings go through `self.finding()`, which clamps scores and derives severity.

## Scoring signals

Fixed scores per rule, ordered by how close the damage is:

- Expiring <14 days (95, critical): outage or browser trust errors are
  imminent; renew immediately.
- Expiring <30 days (80, high): inside a single renewal cycle — schedule
  now, automate if possible.
- Expiring <60 days (55, medium): put it on the calendar; not urgent.
- SHA-1/MD5 signature algorithm (75, high): forgeable certificates, MITM
  exposure — reissue with SHA-256 or better.
- Key smaller than 2048 bits (70, high): crackable key material —
  reissue at 2048-bit RSA or ECDSA P-256.
- SAN/hostname mismatch (50, medium): the cert doesn't cover the host it
  serves — broken trust, possible mis-issuance.

A certificate more than 60 days out, with a strong signature and key, and
valid SANs produces no findings — silence means healthy.

## Configuration

The rule thresholds (14/30/60 days, SHA-1/MD5 tokens, 2048-bit floor) are
fixed in the module. The engine takes no options beyond enabled:

```yaml
engines:
  tls_watch:
    enabled: true
```

Certificates under watch are supplied with the scan as `ctx.data["tls_certs"]`:

```yaml
# scan input shape (illustrative)
tls_certs:
  - host: "www.romansproposal.com"
    not_after: "2026-12-01T00:00:00+00:00"
    sig_alg: "sha256WithRSAEncryption"
    key_bits: 2048
    san_ok: true
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2C9P6B0LYVW8MDXA2TE2F",
  "engine": "tls_watch",
  "title": "Certificate expiring imminently: donations.example.org",
  "severity": "critical",
  "score": 95.0,
  "entities": {
    "host": "donations.example.org"
  },
  "evidence": {
    "host": "donations.example.org",
    "not_after": "2026-10-10T12:00:00+00:00",
    "days_remaining": 7.5
  },
  "recommendation": "Renew the certificate for donations.example.org immediately — expiry causes browser trust errors and downtime.",
  "tags": ["tls", "expiry", "availability"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
