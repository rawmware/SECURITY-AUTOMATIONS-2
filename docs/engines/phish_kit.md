# phish_kit

Fingerprints phishing kits in web page HTML via weighted marker matching.

## The attack it stops

A buyer clicks a "reset your password" link from an email that spoofed
their bank's domain. The page looks identical to the real login — because
the attacker bought a $30 phishing kit and cloned it. The form posts
credentials to `api.telegram.org/bot…`, an obfuscated script blocks
inspection, and a hidden iframe loads a second skimmer. Password, account
number, and one-time code are harvested in one session; by evening the
attacker has wired money out through a mule network.

## How detection works

`phish_kit` is a `base.Engine` subclass registered with `@register`,
`name = "phish_kit"`. On `scan(ctx)` it reads pages from `ctx.data["pages"]` — a mapping of `url → html` fetched upstream through the `http_get` ScanContext hook (the engine never fetches pages itself).

Each page's HTML is matched against a fixed set of markers, each with a
weight:

- `credential_harvester` (30): `<input type="password">` — the harvest
  form itself.
- `telegram_exfil` (40): `api.telegram.org/bot` — the most common kit
  exfil endpoint.
- `obfuscated_js` (25): `eval(unescape(` — packed/obfuscated script.
- `hidden_iframe` (20): `<iframe … display:none` — concealed skimmer.
- `brand_impersonation` (15): "verify/confirm … account/identity" phrasing.
- `external_form_post` (25): form posting to a foreign domain (the brand's own domain from `ctx.targets["domain"]` is excluded).

The weights of matched markers are summed and capped at 100; pages scoring at or above `min_score` become findings via `self.finding()`, with matched markers and weights in the evidence. One or two markers — a legitimate login page — stay quiet.

## Scoring signals

Weights, not raw severity: the sum decides, capped at 100.

- Telegram exfil endpoint (40): the single strongest marker.
- Password input (30): every phishing kit needs the harvest form.
- External form post to a foreign domain (25): the kit's business model — credentials leaving the page.
- Obfuscated JavaScript (25): `eval(unescape(` packing, anti-analysis.
- Hidden iframe (20): concealed skimmer or secondary payload.
- Brand-bait phrasing (15): "verify your account" urgency copy.

A page with Telegram exfil + password form + external post scores 95
(critical). A plain login page with only a password input scores 30 and
stays below the default threshold of 35. Matched markers are appended to
the finding's tags, so triage shows the fingerprints directly.

## Configuration

```yaml
engines:
  phish_kit:
    enabled: true
    min_score: 35   # flag pages scoring at or above this threshold
```

Pages under inspection are supplied with the scan as `ctx.data["pages"]`
(url → HTML). The brand domain comes from scan targets and excludes the brand's own forms from the external-post marker:

```yaml
targets:
  domain: "romansproposal.com"
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2JG3I7SFDE5UKEH9AL9N",
  "engine": "phish_kit",
  "title": "Phishing-kit indicators on https://secure-login-update.top/invoice",
  "severity": "critical",
  "score": 95.0,
  "entities": {
    "url": "https://secure-login-update.top/invoice"
  },
  "evidence": {
    "matched_markers": [
      "credential_harvester",
      "telegram_exfil",
      "external_form_post"
    ],
    "marker_weights": {
      "credential_harvester": 30,
      "telegram_exfil": 40,
      "external_form_post": 25
    },
    "min_score": 35
  },
  "recommendation": "Take https://secure-login-update.top/invoice down and preserve it for forensics. Extract the exfil destination (e.g. Telegram bot token) and search mail gateways / proxy logs for victims who visited it.",
  "tags": ["phishing", "web", "credential_harvester", "telegram_exfil", "external_form_post"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
