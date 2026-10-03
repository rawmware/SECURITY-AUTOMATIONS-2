# auth_watch

Detects brute-force, password-spray, and distributed (low-and-slow) credential attacks in auth logs.

## The attack it stops

On a Monday morning, the HR director at a 40-person firm finds she can't
log in — her password was changed overnight. The attacker had spent the
weekend spraying the company's VPN with `Company2026!` across every
username, three tries per account to dodge the lockout. One weak password
was enough. Once inside, they quietly exfiltrated payroll files for two
weeks before a routine audit caught the anomaly. The company paid for
credit monitoring for every employee and lost a client over the disclosure.
The logs contained the whole attack — nobody was reading them.

## How detection works

`auth_watch` is a `base.Engine` subclass registered with `@register`,
`name = "auth_watch"`. On `scan(ctx)` it reads auth log text from
`ctx.data["auth_log"]` (fed via the `read_file` ScanContext hook upstream)
and parses lines of the form `ISO8601 ip user result`, where result is
`ok` or `fail`; malformed lines are skipped.

From the failure events it builds three indexes and runs three checks:

1. **Brute force** — sliding window over each IP's failure timestamps: the
   peak count inside any `window_minutes` window that reaches
   `fail_threshold` → finding at 85 (high).
2. **Password spray** — distinct usernames failing from one IP reaching
   `spray_users` → finding at 85 (high). This catches the few-passwords /
   many-accounts pattern that dodges per-account lockouts.
3. **Distributed attack** — distinct source IPs failing for one user
   reaching `spray_ips` → finding at 60 (medium). Catches low-and-slow
   attacks spread across a botnet.

Findings go through `self.finding()`, which clamps scores and derives
severity from the standard bands. Evidence includes the peak counts,
thresholds, targeted users, and source IPs so triage starts immediately.

## Scoring signals

Fixed scores per pattern:

- Brute force from one IP (85, high): peak failures in the window at or
  above `fail_threshold` (default 8 fails in 10 minutes). High because it is
  unambiguous and actively running.
- Password spray from one IP (85, high): `spray_users` (default 5) distinct
  users failing from the same source. High because it targets the weakest
  password, not the weakest lockout.
- Distributed attack on one user (60, medium): `spray_ips` (default 5)
  distinct source IPs. Medium because no single IP looks abusive — it needs
  correlation, not a firewall rule.

Raising `fail_threshold` or `window_minutes` reduces noise on noisy public
services at the cost of missing slower attacks; the spray checks catch what
brute-force thresholds miss.

## Configuration

```yaml
engines:
  auth_watch:
    enabled: true
    fail_threshold: 8      # fails from one IP inside the window -> brute force
    window_minutes: 10     # sliding window for the brute-force peak count
    spray_users: 5         # distinct users failing from one IP -> spray
    spray_ips: 5           # distinct IPs failing for one user -> distributed
```

Log lines (supplied via `ctx.data["auth_log"]`) are `ISO8601 ip user result`:

```
2026-10-03T17:42:01+00:00 203.0.113.77 jdoe fail
2026-10-03T17:42:09+00:00 203.0.113.77 jdoe fail
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2EB8D2NAYXY0PFZC4VG4H",
  "engine": "auth_watch",
  "title": "Password-spray attack from 203.0.113.77",
  "severity": "high",
  "score": 85.0,
  "entities": {
    "ip": "203.0.113.77"
  },
  "evidence": {
    "ip": "203.0.113.77",
    "distinct_users": ["agarcia", "bwong", "jdoe", "kpatel", "rsmith"],
    "user_count": 5,
    "threshold": 5
  },
  "recommendation": "Block 203.0.113.77; it is testing common passwords across many accounts to dodge per-account lockouts. Review all targeted accounts.",
  "tags": ["password-spray", "credential-attack", "auth"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
