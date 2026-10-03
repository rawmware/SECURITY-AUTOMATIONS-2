"""CVE Watch — match installed dependencies against known vulnerabilities.

The real attack: attackers don't need zero-days when your library is three
years old. Unpatched-dependency exploitation (Log4Shell, MOVEit, Struts) is
the highest-ROI attack vector in existence: public exploit, known version
string, automated mass scanning. This engine takes a software bill of
materials (SBOM) plus a CVE feed and matches package names against vulnerable
version specs, so you learn about the vulnerable library before the attacker
does.
"""

from __future__ import annotations

import re

from aegis.engines import Engine, register
from aegis.engines.base import ScanContext
from aegis.utils import clamp

_SPEC_RE = re.compile(r"^\s*(<=|<|==)\s*([0-9A-Za-z.\-+]+)\s*$")


def parse_version(raw: str) -> tuple[int, ...]:
    """Parse a version string into an int tuple, stripping non-numeric
    suffixes (``1.2.3-beta`` -> ``(1, 2, 3)``). Missing/invalid components
    become 0."""
    parts: list[int] = []
    for chunk in str(raw or "").strip().split("."):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group(0)) if m else 0)
    return tuple(parts) if parts else (0,)


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(a), len(b))
    return (
        tuple(a) + (0,) * (width - len(a)),
        tuple(b) + (0,) * (width - len(b)),
    )


def version_matches(version: str, spec: str) -> bool:
    """Evaluate an affected-version spec (``<1.2.3``, ``<=2.0``, ``==1.0.0``,
    comma-separated conjunctions allowed) against an installed version."""
    installed = parse_version(version)
    for clause in spec.split(","):
        m = _SPEC_RE.match(clause)
        if not m:
            return False
        op, target = m.group(1), m.group(2)
        a, b = _pad(installed, parse_version(target))
        if op == "<" and not (a < b):
            return False
        if op == "<=" and not (a <= b):
            return False
        if op == "==" and not (a == b):
            return False
    return True


@register
class CveWatch(Engine):
    """Matches SBOM dependencies against a CVE feed."""

    name = "cve_watch"
    version = "1.0.0"
    description = (
        "Matches installed dependency versions against known CVEs by "
        "package name and affected-version spec."
    )

    def scan(self, ctx: ScanContext) -> list:
        sbom: list = ctx.data.get("sbom") or []
        feed: list = ctx.data.get("cve_feed") or []
        findings: list = []
        seen: set[str] = set()

        # Index installed packages by lowercase name (first entry wins).
        installed: dict[str, dict] = {}
        for comp in sbom:
            name = str(comp.get("name", "")).lower()
            if name and name not in installed:
                installed[name] = comp

        for entry in feed:
            pkg = str(entry.get("package", "")).lower()
            comp = installed.get(pkg)
            if comp is None:
                continue
            affected = entry.get("affected", "")
            version = str(comp.get("version", ""))
            if not affected or not version_matches(version, affected):
                continue
            cve_id = entry.get("cve_id", "CVE-UNKNOWN")
            key = f"{pkg}@{version}:{cve_id}"
            if key in seen:
                continue
            seen.add(key)
            cvss = float(entry.get("cvss", 0.0) or 0.0)
            fixed_in = entry.get("fixed_in", "unknown")
            findings.append(
                self.finding(
                    title=f"{cve_id}: {comp.get('name')} {version} is vulnerable",
                    score=clamp(cvss * 10.0),
                    entities={"package": comp.get("name"), "version": version},
                    evidence={
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "affected": affected,
                        "fixed_in": fixed_in,
                        "summary": entry.get("summary", ""),
                    },
                    recommendation=(
                        f"Upgrade {comp.get('name')} to {fixed_in} or later. "
                        "If an upgrade is not possible, check the vendor for "
                        "mitigations and monitor for exploitation attempts."
                    ),
                    tags=["vulnerability", "dependency", cve_id],
                )
            )
        return findings
