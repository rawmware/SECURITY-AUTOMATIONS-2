# canary_trip

Honeytoken tripwires: mints fake credentials and fires a critical finding the instant one is touched.

## The attack it stops

An intruder gains a foothold on a dev server through an unpatched service
and starts rummaging. They grep the home directory for AWS keys and find
`AKIA…` hardcoded in an old backup script — except that key is a canary,
planted there by the defenders. It has never been used legitimately, so the
moment it appears in a CloudTrail log or the attacker tries it, the alarm
fires. Instead of discovering the breach weeks later during a routine
review, the team has proof of an active intruder within minutes, isolates
the server, and rotates the real credentials that lived nearby. The canary
didn't stop the break-in — it made the break-in impossible to miss.

## How detection works

`canary_trip` is a `base.Engine` subclass registered with `@register`,
`name = "canary_trip"`. It works in two halves. `mint_canary(kind)` (a
module-level helper) generates a realistic honeytoken of kind `aws`
(`AKIA` + 16 random chars), `url`
(`https://canary-<rand>.example.net/ping`), or `cred`
(`canary_svc_` + 12 chars), each with a unique `canary_*` id. The operator
plants the token where only an intruder would find it: a backup script, an
old config, a private document.

On `scan(ctx)` the engine reads the planted canaries from
`ctx.data["canaries"]` and sightings from `ctx.data["sightings"]` (log
lines, repo diffs, proxy hits — fed through ScanContext hooks upstream). The
first sighting containing a canary's token emits one finding at score 100
(critical); duplicates dedupe by canary id.

A sighting is proof of handling, not a probability — no scoring model, no
threshold, no false-positive math. The raw token is never echoed in
evidence: findings record canary id, kind, location, and `first_seen` (from
`ctx.now_iso()`).

## Scoring signals

There are no scoring signals — the design is binary:

- Canary token appears in any sighting (100, critical): someone touched a
  secret that exists only to be stolen — treat as active intrusion.
- No sighting contains the token: no finding. Silence is the normal state.

Because canary hits are near-zero-noise by construction, the recommendation
is direct: isolate, preserve logs, rotate adjacent credentials, and start
incident response.

## Configuration

The engine takes no options beyond enabled — canaries and sightings are
scan inputs:

```yaml
engines:
  canary_trip:
    enabled: true
```

Scan inputs (illustrative):

```yaml
# ctx.data["canaries"] — planted tokens, minted with mint_canary()
canaries:
  - id: "canary_9f2a"
    kind: "aws"
    token: "AKIAX7Q2M9K4PL8TW6Z1"
    location: "/opt/backups/nightly.sh"

# ctx.data["sightings"] — text searched for token appearances
sightings:
  - "grep results from host dev-03 ..."
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2LI5K9UHFGG7WMGJ1CN1P",
  "engine": "canary_trip",
  "title": "Honeytoken tripped: canary_9f2a",
  "severity": "critical",
  "score": 100.0,
  "entities": {
    "canary_id": "canary_9f2a",
    "kind": "aws"
  },
  "evidence": {
    "canary_id": "canary_9f2a",
    "kind": "aws",
    "location": "/opt/backups/nightly.sh",
    "first_seen": "2026-10-03T18:00:00+00:00"
  },
  "recommendation": "Treat as an active intrusion. Isolate the system that emitted the sighting, preserve logs, rotate every credential that lived near the canary, and start incident response — someone handled this token.",
  "tags": ["canary", "honeytoken", "intrusion"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
