"""Canary Trip — honeytoken tripwire detection.

The real attack: intruders rummage. They grep repos for AWS keys, scrape
logs for tokens, follow suspicious URLs in configs. A canary token is a fake
credential planted where only an intruder would touch it — a bogus AWS key
in a backup script, a fake service password in an old config, a unique URL
in a private document. The moment that token shows up in a log, a repo, or
traffic, you don't have an alert, you have proof someone is inside your
house. This engine mints realistic-looking canaries and fires a critical
finding the instant any sighting contains one.
"""

from __future__ import annotations

import secrets
import string

from aegis.engines import Engine, register
from aegis.engines.base import ScanContext
from aegis.utils import new_id

_ALNUM_UPPER = string.ascii_uppercase + string.digits


def mint_canary(kind: str = "aws") -> dict:
    """Mint a new honeytoken. Returns ``{"id", "kind", "token"}`` — plant
    the token where only an intruder would find it, then feed sightings
    (log lines, repo diffs, proxy hits) into the engine.

    kinds:
      ``aws``  — realistic AWS access key: ``AKIA`` + 16 chars
      ``url``  — unique canary URL: ``https://canary-<rand>.example.net/ping``
      ``cred`` — fake service credential: ``canary_svc_`` + 12 chars
    """
    if kind == "url":
        token = f"https://canary-{secrets.token_hex(4)}.example.net/ping"
    elif kind == "cred":
        token = "canary_svc_" + secrets.token_hex(6)
    else:  # "aws" (default)
        kind = "aws"
        token = "AKIA" + "".join(
            secrets.choice(_ALNUM_UPPER) for _ in range(16)
        )
    return {"id": new_id("canary"), "kind": kind, "token": token}


@register
class CanaryTrip(Engine):
    """Fires a critical finding when a planted canary token appears in any
    sighting (logs, repos, traffic)."""

    name = "canary_trip"
    version = "1.0.0"
    description = (
        "Detects honeytoken tripwires: a planted canary token seen in "
        "sightings means an intruder touched it."
    )

    def scan(self, ctx: ScanContext) -> list:
        canaries: list = ctx.data.get("canaries") or []
        sightings: list = ctx.data.get("sightings") or []
        findings: list = []
        seen_ids: set[str] = set()

        for canary in canaries:
            token = canary.get("token")
            if not token or canary.get("id") in seen_ids:
                continue
            for sighting in sightings:
                if token in str(sighting or ""):
                    canary_id = canary.get("id")
                    seen_ids.add(canary_id)
                    findings.append(
                        self.finding(
                            title=f"Honeytoken tripped: {canary_id}",
                            score=100,
                            entities={
                                "canary_id": canary_id,
                                "kind": canary.get("kind"),
                            },
                            evidence={
                                "canary_id": canary_id,
                                "kind": canary.get("kind"),
                                "location": canary.get("location", "unknown"),
                                "first_seen": ctx.now_iso(),
                                # NOTE: the raw token is never echoed in
                                # evidence — it stays a secret.
                            },
                            recommendation=(
                                "Treat as an active intrusion. Isolate the "
                                "system that emitted the sighting, preserve "
                                "logs, rotate every credential that lived "
                                "near the canary, and start incident "
                                "response — someone handled this token."
                            ),
                            tags=["canary", "honeytoken", "intrusion"],
                        )
                    )
                    break
        return findings
