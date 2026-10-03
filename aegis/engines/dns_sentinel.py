"""DNS baseline drift: catch hijacks, takeovers, and stealthy reroutes.

Real-world attack this stops: DNS hijacking and subdomain takeover. If an
attacker compromises the registrar/DNS provider or claims a dangling CNAME,
they can reroute ``mail`` or ``www`` to infrastructure they control and
intercept traffic, email, and credentials — often with zero alerts. This
engine diffs current DNS answers against a known-good baseline: NS/MX changes
(mean mail flow or authority moved) are critical, A/AAAA changes (traffic
rerouted) are high, TXT changes (SPF/DKIM/verification tokens) are lower.
"""

from __future__ import annotations

from aegis.engines import register
from aegis.engines.base import Engine, ScanContext
from aegis.models import Finding

_RTYPES = ("A", "AAAA", "MX", "TXT", "NS")
_CHANGE_SCORES = {"NS": 80, "MX": 80, "A": 55, "AAAA": 55, "TXT": 30}
_SEVERITY_WORD = {80: "critical", 55: "high", 30: "elevated"}


@register
class DnsSentinel(Engine):
    """Diffs live DNS answers against a known-good baseline per host+rtype."""

    name = "dns_sentinel"
    version = "1.0.0"
    description = (
        "Compares current DNS records for watched hosts against a baseline. "
        "NS/MX drift signals possible hijack; A/AAAA drift signals traffic "
        "rerouting; TXT drift signals verification/SPF tampering."
    )

    def scan(self, ctx: ScanContext) -> list[Finding]:
        hosts = ctx.targets.get("dns_hosts") or []
        baseline = ctx.data.get("dns_baseline") or {}
        findings: list[Finding] = []

        for host in hosts:
            base = baseline.get(host)
            if base is None:
                # Host never seen in the baseline at all: new attack surface.
                current = {rt: list(ctx.dns_resolve(host, rt) or []) for rt in _RTYPES}
                if any(current.values()):
                    findings.append(
                        self.finding(
                            title=f"New host discovered outside baseline: {host}",
                            score=55,
                            entities={"host": host},
                            evidence={
                                "host": host,
                                "current": current,
                                "new_host": True,
                            },
                            recommendation=(
                                f"Verify {host} is an authorized asset. If not, "
                                "it may be a shadow IT deployment or an "
                                "attacker-controlled subdomain."
                            ),
                            tags=["dns", "baseline-drift", "new-host"],
                        )
                    )
                continue

            for rtype in _RTYPES:
                base_vals = set(base.get(rtype, []) or [])
                cur_vals = set(ctx.dns_resolve(host, rtype) or [])
                if base_vals == cur_vals:
                    continue
                added = sorted(cur_vals - base_vals)
                removed = sorted(base_vals - cur_vals)
                score = _CHANGE_SCORES[rtype]
                findings.append(
                    self.finding(
                        title=f"DNS drift on {host} ({rtype} records changed)",
                        score=score,
                        entities={"host": host, "rtype": rtype},
                        evidence={
                            "host": host,
                            "rtype": rtype,
                            "added": added,
                            "removed": removed,
                            "baseline": sorted(base_vals),
                            "current": sorted(cur_vals),
                        },
                        recommendation=(
                            f"{rtype} records for {host} changed outside the "
                            "baseline. Confirm the change was authorized; if "
                            "not, treat as a possible DNS hijack and rotate "
                            "registrar credentials."
                        ),
                        tags=["dns", "baseline-drift", rtype.lower()],
                    )
                )
        return findings
