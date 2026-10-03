# secret_sentry

Scans text sources (repos, configs, logs) for leaked credentials; redacts secrets in evidence.

## The attack it stops

A junior developer is debugging a payment integration late at night and
pastes an AWS access key into a Slack channel, then commits a config file
with the key hardcoded and pushes to the team's public GitHub repo. GitHub's
secret scanning fires an alert — but attackers run automated scanners
faster. Within eleven minutes a bot has cloned the repo, extracted the key,
and spun up forty GPU instances in us-east-1 for crypto mining. The team
wakes up to a $12,000 cloud bill and a forced key rotation across every
service that shared the credential. The key was real for nine hours.

## How detection works

`secret_sentry` is a `base.Engine` subclass registered with `@register`,
`name = "secret_sentry"`. On `scan(ctx)` it reads text sources from
`ctx.data["texts"]` — a mapping of `source_name → text`, fed via the
`read_file` ScanContext hook upstream (repos, config files, logs, dumps).
The engine never reads files directly and never logs raw secrets: every
finding's evidence carries only a redacted preview (first 4 chars plus an
ellipsis) and a SHA-256 digest of the secret for correlation.

Detection runs five passes over each text:

1. AWS access keys: `AKIA` + 16 chars → score 90.
2. AWS secret keys: 40-char base64-ish token with an `aws_secret` label
   within 100 chars (bare 40-char strings are too noisy alone) → 90.
3. GitHub tokens: `ghp_`/`gho_`/`github_pat_` prefixes → 85.
4. Private key blocks: `-----BEGIN [RSA ]PRIVATE KEY-----` → 95.
5. Generic `key=value` pairs (api_key, secret, token, password…) with
   value entropy ≥ 4.2 bits/char (Shannon gate — `password=changeme123`
   never fires) → 70.

Duplicates are deduped by secret digest across sources, and an allowlist
(option) suppresses known test/example values.

## Scoring signals

Fixed per pattern type, ordered by how directly the secret hands an
attacker a foothold:

- Private key material (95, critical): full identity theft of the
  associated server/service — revoke and rotate immediately.
- AWS access key / AWS secret key (90, critical): direct infrastructure
  access; bots exploit these in minutes.
- GitHub token (85, high): repo and org access; source-code theft and
  supply-chain risk.
- Generic hardcoded credential (70, high): the entropy gate keeps
  precision high, so a hit means a real-looking secret.

Severity comes straight from these scores through the standard bands
(≥90 critical, ≥70 high). There is no low-signal output by design — the
patterns and entropy gate are deliberately narrow.

## Configuration

The entropy floor (4.2) and pattern list are fixed in the module. The
allowlist is configurable:

```yaml
engines:
  secret_sentry:
    enabled: true
    allowlist:
      - "AKIAIOSFODNN7EXAMPLE"   # documented example keys, test fixtures
```

Text sources are supplied with the scan as `ctx.data["texts"]` (source
name → text). Evidence always carries `preview` (redacted) and `sha`
(digest) — never the raw secret.

## Sample finding

```json
{
  "id": "fnd_01K9Q2GD0F4PCAZA2RHBE6XI6K",
  "engine": "secret_sentry",
  "title": "AWS access key exposed in deploy/config.py",
  "severity": "critical",
  "score": 90.0,
  "entities": {
    "source": "deploy/config.py",
    "secret_type": "aws_access_key"
  },
  "evidence": {
    "pattern": "aws_access_key",
    "preview": "AKIA…",
    "sha": "a1b2c3d4"
  },
  "recommendation": "Revoke the credential immediately, rotate any dependent secrets, and check audit logs for use of the key (sha a1b2c3d4).",
  "tags": ["credential", "leak", "aws_access_key"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
