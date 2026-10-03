"""Cloud Posture — misconfiguration auditing of cloud control planes.

The real attack: most cloud breaches aren't hacks, they're typos. A public
S3 bucket, a management port open to the world, an IAM policy with
``Action: "*"`` — attackers run internet-wide scanners that find these
mistakes continuously, so the question is never *if* but *when*. This engine
audits a cloud snapshot (buckets, security groups, IAM policies, volumes)
for the classic misconfigurations and scores them by how directly they hand
an attacker a foothold.
"""

from __future__ import annotations

from aegis.engines import Engine, register
from aegis.engines.base import ScanContext

#: Ports that should never be world-reachable: SSH, RDP, SMB, and the
#: default database/admin ports attackers sweep first.
SENSITIVE_PORTS = {22, 3389, 445, 3306, 5432, 6379, 27017, 9200}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}

ADMIN_ACTION = "*"


@register
class CloudPosture(Engine):
    """Audits cloud configuration for public buckets, open security groups,
    over-privileged IAM, and unencrypted volumes."""

    name = "cloud_posture"
    version = "1.0.0"
    description = (
        "Flags cloud misconfigurations: public S3 buckets, world-open "
        "security-group ingress on sensitive ports, wildcard IAM actions, "
        "and unencrypted volumes."
    )

    def scan(self, ctx: ScanContext) -> list:
        cloud: dict = ctx.data.get("cloud") or {}
        findings: list = []
        findings.extend(self._check_buckets(cloud.get("s3_buckets") or []))
        findings.extend(self._check_security_groups(cloud.get("security_groups") or []))
        findings.extend(self._check_iam(cloud.get("iam_policies") or []))
        findings.extend(self._check_volumes(cloud.get("volumes") or []))
        return findings

    # -- rules ------------------------------------------------------------
    def _check_buckets(self, buckets: list) -> list:
        out = []
        for bucket in buckets:
            if not bucket.get("public_read"):
                continue
            name = bucket.get("name", "<unnamed>")
            out.append(
                self.finding(
                    title=f"Public S3 bucket: {name}",
                    score=80,
                    entities={"bucket": name},
                    evidence={"public_read": True, "name": name},
                    recommendation=(
                        f"Make s3://{name} private unless it is intentionally "
                        "a public asset. Enable Block Public Access and audit "
                        "object ACLs; assume listed contents were crawled."
                    ),
                    tags=["cloud", "s3", "misconfiguration"],
                )
            )
        return out

    def _check_security_groups(self, groups: list) -> list:
        out = []
        for sg in groups:
            sg_id = sg.get("id", "<unnamed>")
            for rule in sg.get("ingress") or []:
                try:
                    port = int(rule.get("port", -1))
                except (TypeError, ValueError):
                    continue
                cidr = str(rule.get("cidr", ""))
                if port in SENSITIVE_PORTS and cidr in WORLD_CIDRS:
                    out.append(
                        self.finding(
                            title=f"Security group {sg_id}: port {port} open to the world",
                            score=90,
                            entities={"security_group": sg_id, "port": port},
                            evidence={"ingress": {"port": port, "cidr": cidr}},
                            recommendation=(
                                f"Restrict ingress on port {port} in {sg_id} to "
                                "known bastion/VPN ranges. Assume this port "
                                "has been brute-forced continuously."
                            ),
                            tags=["cloud", "security-group", "exposure"],
                        )
                    )
        return out

    def _check_iam(self, policies: list) -> list:
        out = []
        for policy in policies:
            actions = policy.get("actions") or policy.get("Action") or []
            if ADMIN_ACTION not in [str(a) for a in actions]:
                continue
            name = policy.get("name", "<unnamed>")
            out.append(
                self.finding(
                    title=f"IAM policy {name} grants wildcard Action",
                    score=85,
                    entities={"policy": name},
                    evidence={"actions": list(actions)},
                    recommendation=(
                        f"Replace the wildcard action in {name} with "
                        "least-privilege actions scoped to the resources the "
                        "principal actually needs."
                    ),
                    tags=["cloud", "iam", "privilege"],
                )
            )
        return out

    def _check_volumes(self, volumes: list) -> list:
        out = []
        for volume in volumes:
            if volume.get("encrypted"):
                continue
            vol_id = volume.get("id", "<unnamed>")
            out.append(
                self.finding(
                    title=f"Unencrypted volume: {vol_id}",
                    score=55,
                    entities={"volume": vol_id},
                    evidence={"encrypted": False, "id": vol_id},
                    recommendation=(
                        f"Enable encryption at rest for {vol_id}. Snapshots "
                        "and detached volumes of unencrypted disks are "
                        "readable by anyone who can copy them."
                    ),
                    tags=["cloud", "storage", "encryption"],
                )
            )
        return out
