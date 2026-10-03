"""Attack-surface drift watch: catch exposed services and silent outages.

Real-world attack this stops: misconfigured firewalls and forgotten services
expose dangerous ports (RDP/3389, SMB/445, Redis/6379, databases) to the
internet — the entry point for ransomware and data theft. Conversely, a port
you expect to be open going dark means a service died silently. This engine
diffs the observed open ports against the expected baseline: unexpected opens
are scored by how dangerous the port is, expected-but-closed ports raise a
low-severity availability notice.
"""

from __future__ import annotations

from aegis.engines import register
from aegis.engines.base import Engine, ScanContext
from aegis.models import Finding

#: Inherent risk of an exposed port if it was never supposed to be open.
PORT_RISK = {
    23: 90,  # telnet — cleartext, never belongs on the internet
    445: 85,  # SMB — ransomware's favourite door
    3389: 80,  # RDP — brute-forced constantly
    5900: 75,  # VNC — often weak or no auth
    6379: 70,  # Redis — frequently unauthenticated
    3306: 65,  # MySQL
    5432: 65,  # PostgreSQL
    27017: 70,  # MongoDB
    9200: 70,  # Elasticsearch
    21: 60,  # FTP — cleartext credentials
    22: 25,  # SSH — normal, but unexpected is still suspicious
    80: 10,  # HTTP — usually intentional
    443: 10,  # HTTPS — usually intentional
}
DEFAULT_RISK = 40

_PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}


@register
class PortWatch(Engine):
    """Diffs observed open ports against the expected baseline per host."""

    name = "port_watch"
    version = "1.0.0"
    description = (
        "Compares the current port scan against expected open ports. "
        "Unexpected opens are scored by port risk; expected-but-closed "
        "ports raise an availability notice."
    )

    def scan(self, ctx: ScanContext) -> list[Finding]:
        port_scan = ctx.data.get("port_scan") or {}
        expected = ctx.data.get("expected_ports") or {}
        findings: list[Finding] = []

        for host in sorted(set(port_scan) | set(expected)):
            open_ports = {int(p) for p in (port_scan.get(host) or [])}
            expected_ports = {int(p) for p in (expected.get(host) or [])}

            for port in sorted(open_ports - expected_ports):
                risk = PORT_RISK.get(port, DEFAULT_RISK)
                svc = _PORT_NAMES.get(port, "unknown service")
                findings.append(
                    self.finding(
                        title=f"Unexpected open port {port} ({svc}) on {host}",
                        score=risk,
                        entities={"host": host, "port": port, "service": svc},
                        evidence={
                            "host": host,
                            "port": port,
                            "service": svc,
                            "port_risk": risk,
                            "expected_ports": sorted(expected_ports),
                            "open_ports": sorted(open_ports),
                        },
                        recommendation=(
                            f"Port {port} ({svc}) is reachable on {host} but "
                            "not in the expected baseline. Confirm it is "
                            "intentional; otherwise close it at the firewall."
                        ),
                        tags=["attack-surface", "exposed-port", "firewall"],
                    )
                )

            for port in sorted(expected_ports - open_ports):
                svc = _PORT_NAMES.get(port, "unknown service")
                findings.append(
                    self.finding(
                        title=f"Expected service down: port {port} ({svc}) closed on {host}",
                        score=10,
                        entities={"host": host, "port": port, "service": svc},
                        evidence={
                            "host": host,
                            "port": port,
                            "service": svc,
                            "expected_ports": sorted(expected_ports),
                            "open_ports": sorted(open_ports),
                        },
                        recommendation=(
                            f"Port {port} ({svc}) should be open on {host} but "
                            "is not responding. The service may be down or "
                            "the firewall rule may have changed."
                        ),
                        tags=["attack-surface", "availability"],
                    )
                )
        return findings
