"""Stage 2 — enrich. Weigh a finding against business context: how critical
are the assets it touches?"""

from __future__ import annotations

from aegis.models import Finding

CROWN_JEWEL_CRITICALITY = 4
DEFAULT_CRITICALITY = 2


def enrich(finding: Finding, ctx_assets: dict) -> dict:
    """Look up each entity in the asset-criticality map ``{entity: 1..5}``.

    Returns ``{asset_criticality, is_crown_jewel, entity_count}`` where
    ``asset_criticality`` is the maximum criticality across the finding's
    entities (defaulting to 2 when an entity is unknown) and
    ``is_crown_jewel`` is true when that maximum reaches 4 or higher.
    """
    values = [str(v) for v in finding.entities.values()]
    crits = [
        max(1, min(5, int(ctx_assets.get(v, DEFAULT_CRITICALITY))))
        for v in values
    ]
    criticality = max(crits) if crits else DEFAULT_CRITICALITY
    return {
        "asset_criticality": criticality,
        "is_crown_jewel": criticality >= CROWN_JEWEL_CRITICALITY,
        "entity_count": len(finding.entities),
    }
