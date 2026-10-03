"""Stage 3 — score. Blend the engine's raw score with asset criticality and
detection confidence into one adjusted 0–100 risk score."""

from __future__ import annotations

from aegis.models import Finding, ScoredFinding, severity_for_score
from aegis.utils import clamp


def score_finding(
    finding: Finding,
    enrichment: dict,
    confidence: float = 0.85,
) -> ScoredFinding:
    """Adjust ``finding.score`` for asset criticality and confidence::

        adjusted = clamp(base * (0.70 + 0.12*criticality) * (0.6 + 0.4*confidence))

    Critical assets amplify the score; low confidence dampens it. The result
    is rounded to one decimal place and mapped to a severity label.
    """
    criticality = int(enrichment.get("asset_criticality", 2))
    confidence = max(0.0, min(1.0, float(confidence)))
    multiplier = (0.70 + 0.12 * criticality) * (0.6 + 0.4 * confidence)
    adjusted = round(clamp(finding.score * multiplier), 1)
    factors = {
        "base_score": round(finding.score, 1),
        "criticality": criticality,
        "confidence": confidence,
        "multiplier": round(multiplier, 3),
    }
    return ScoredFinding(
        finding=finding,
        adjusted_score=adjusted,
        adjusted_severity=severity_for_score(adjusted),
        factors=factors,
    )
