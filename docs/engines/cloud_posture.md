# cloud_posture

Audits a cloud snapshot for classic misconfigurations: public storage, world-open security groups, wildcard IAM, unencrypted volumes.

## The attack it stops

A marketing team uploads a product photo to a storage bucket and, following
a tutorial, makes the bucket public so the image embeds in a newsletter.
Nobody notices the bucket also holds last quarter's customer export — a CSV
with 40,000 names, emails, and addresses. Internet-wide bucket scanners
find the public bucket in days; the CSV appears for sale on a forum within
a month. The company pays for breach notification and a year of credit
monitoring per affected person, and the CMO spends the quarter answering
regulators. The misconfiguration took thirty seconds and was entirely
accidental.

## How detection works

`cloud_posture` is a `base.Engine` subclass registered with `@register`,
`name = "cloud_posture"`. On `scan(ctx)` it reads a cloud snapshot from
`ctx.data["cloud"]` — four lists: `s3_buckets`, `security_groups`,
`iam_policies`, and `volumes` — and runs four independent rule checks:

1. **Buckets**: any bucket with `public_read` true → finding at 80.
2. **Security groups**: any ingress rule opening a sensitive port
   (22, 3389, 445, 3306, 5432, 6379, 27017, 9200) to a world CIDR
   (`0.0.0.0/0`, `::/0`) → finding at 90.
3. **IAM policies**: any policy whose actions include the wildcard `*` →
   finding at 85.
4. **Volumes**: any volume with `encrypted` not true → finding at 55.

The engine performs no cloud API calls — the snapshot is supplied with the
scan — and each finding goes through `self.finding()`, which clamps scores
and derives severity from the standard bands.

## Scoring signals

Fixed per rule, by how directly the misconfiguration hands an attacker a
foothold:

- Security group with a sensitive port open to the world (90, critical):
  assume it has been brute-forced continuously.
- IAM policy with wildcard `Action: "*"` (85, high): one compromised key
  inherits the whole account — replace with least-privilege actions.
- Public-read storage bucket (80, high): assume listed contents were
  crawled; block public access and audit object ACLs.
- Unencrypted volume (55, medium): snapshots and detached volumes of
  unencrypted disks are readable by anyone who can copy them.

Silence from a rule means the snapshot is clean on that axis.

## Configuration

The rule set and sensitive-port list are fixed in the module. The engine
takes no options beyond enabled:

```yaml
engines:
  cloud_posture:
    enabled: true
```

The cloud snapshot is supplied with the scan as `ctx.data["cloud"]`:

```yaml
# scan input shape (illustrative)
cloud:
  s3_buckets:
    - name: "product-assets"
      public_read: false
  security_groups:
    - id: "sg-01"
      ingress:
        - {port: 22, cidr: "10.0.0.0/8"}
```

## Sample finding

```json
{
  "id": "fnd_01K9Q2IF2H6RECDC4TJDG8ZK8M",
  "engine": "cloud_posture",
  "title": "Security group sg-01: port 22 open to the world",
  "severity": "critical",
  "score": 90.0,
  "entities": {
    "security_group": "sg-01",
    "port": 22
  },
  "evidence": {
    "ingress": {
      "port": 22,
      "cidr": "0.0.0.0/0"
    }
  },
  "recommendation": "Restrict ingress on port 22 in sg-01 to known bastion/VPN ranges. Assume this port has been brute-forced continuously.",
  "tags": ["cloud", "security-group", "exposure"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```
