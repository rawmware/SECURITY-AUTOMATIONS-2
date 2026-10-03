# port_watch

Diffs observed open ports against an expected baseline to catch new exposure and silent outages.

## The attack it stops

A contractor spins up a Redis instance on a company's cloud server for a
weekend migration task, leaves it listening on 0.0.0.0:6379 with no
password, and forgets it. Shodan indexes the open port within days. An
automated botnet finds it the following week, writes a crypto miner into
the instance, then uses the Redis `CONFIG` trick to drop an SSH key onto
the host. The company discovers the breach only when their cloud bill
triples and outbound connections to a mining pool set off an alert. The
initial exposure — one unexpected open port — existed for nine days and
cost them a full incident response and a rebuilt fleet.

## How detection works

`port_watch` is a `base.Engine` subclass registered with `@register`,
`name = "port_watch"`. On `scan(ctx)` it reads two maps from the context
data: `ctx.data["port_scan"]` (host → list of currently open ports, from the
port-scan feed) and `ctx.data["expected_ports"]` (host → list of ports
expected to be open, the baseline).

For each host in either map it computes the set difference both ways:

- Ports open but not expected → "unexpected open port" finding, scored by
  the module's `PORT_RISK` table (e.g. telnet 90, SMB 85, RDP 80,
  Redis 70, SSH 25, HTTP/HTTPS 10, unknown ports 40).
- Ports expected but not open → "expected service down" finding at score
  10 (low), an availability notice rather than a threat signal.

Ports present in both produce nothing. All findings go through
`self.finding()`, which clamps scores and derives severity from the
standard bands. The engine reads only from ScanContext data — it never
scans ports itself.

## Scoring signals

The `PORT_RISK` table scores an unexpected open by how directly attackers
exploit that service:

- 90 critical — telnet/23 (cleartext, never belongs on the internet).
- 85 high — SMB/445 (ransomware's favorite door).
- 80 high — RDP/3389 (brute-forced constantly).
- 75 high — VNC/5900 (often weak or no auth).
- 70 high — Redis/6379, MongoDB/27017, Elasticsearch/9200 (frequently
  unauthenticated, script-kiddie magnets).
- 65 high — MySQL/3306, PostgreSQL/5432.
- 60 medium — FTP/21 (cleartext credentials).
- 40 medium — any port not in the table (unknown risk, worth a look).
- 25 low — SSH/22 (normal, but unexpected is still suspicious).
- 10 low — HTTP/80, HTTPS/443 (usually intentional).

Expected-but-closed ports always score 10 (low): the service died or the
firewall rule changed, and someone should know.

## Configuration

The risk table is fixed in the module. What you configure is the baseline:

```yaml
engines:
  port_watch:
    enabled: true
```

The expected-port baseline and the observed scan are supplied with each
scan as `ctx.data["expected_ports"]` and `ctx.data["port_scan"]` (host →
port lists). Keep the baseline under change control so every unexpected
open is meaningful rather than stale config.

## Sample finding

```json
{
  "id": "fnd_01K9Q2DA7C1MZXWX9NEYB3UF3G",
  "engine": "port_watch",
  "title": "Unexpected open port 6379 (Redis) on web-01",
  "severity": "high",
  "score": 70.0,
  "entities": {
    "host": "web-01",
    "port": 6379,
    "service": "Redis"
  },
  "evidence": {
    "host": "web-01",
    "port": 6379,
    "service": "Redis",
    "port_risk": 70,
    "expected_ports": [22, 80, 443],
    "open_ports": [22, 80, 443, 6379]
  },
  "recommendation": "Port 6379 (Redis) is reachable on web-01 but not in the expected baseline. Confirm it is intentional; otherwise close it at the firewall.",
  "tags": ["attack-surface", "exposed-port", "firewall"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
