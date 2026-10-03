"""Core data models: the vocabulary every engine, pipeline stage, and
playbook speaks. Plain dataclasses — no framework required to use them."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aegis.utils import new_id, utcnow

SEVERITIES = ("informational", "low", "medium", "high", "critical")

#: Score bands that map a 0–100 risk score onto a severity label.
SCORE_BANDS = (
    (90.0, "critical"),
    (70.0, "high"),
    (40.0, "medium"),
    (10.0, "low"),
    (0.0, "informational"),
)


def severity_for_score(score: float) -> str:
    """Map a 0–100 risk score to a severity label."""
    for threshold, label in SCORE_BANDS:
        if score >= threshold:
            return label
    return "informational"


@dataclass
class Finding:
    """One thing one engine noticed. Immutable-ish; pipeline stages wrap
    findings, they don't mutate them."""

    engine: str
    title: str
    severity: str
    score: float
    entities: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""
    tags: list = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("fnd"))
    ts: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")
        self.score = max(0.0, min(100.0, float(self.score)))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "engine": self.engine,
            "title": self.title,
            "severity": self.severity,
            "score": round(self.score, 1),
            "entities": self.entities,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "tags": list(self.tags),
            "ts": self.ts.isoformat(),
        }


@dataclass
class ScoredFinding:
    """A finding after the pipeline's scoring stage has weighed it against
    asset criticality, confidence, and business context."""

    finding: Finding
    adjusted_score: float
    adjusted_severity: str
    factors: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = self.finding.to_dict()
        d["adjusted_score"] = round(self.adjusted_score, 1)
        d["adjusted_severity"] = self.adjusted_severity
        d["score_factors"] = self.factors
        return d


@dataclass
class Case:
    """A correlated group of findings the correlator believes belong to one
    attacker campaign — an attack chain, not a pile of alerts."""

    title: str
    findings: list = field(default_factory=list)
    severity: str = "medium"
    score: float = 0.0
    entities: dict = field(default_factory=dict)
    narrative: str = ""
    id: str = field(default_factory=lambda: new_id("case"))
    ts: datetime = field(default_factory=utcnow)
    status: str = "open"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "score": round(self.score, 1),
            "status": self.status,
            "entities": self.entities,
            "narrative": self.narrative,
            "finding_ids": [f.id for f in self.findings],
            "ts": self.ts.isoformat(),
        }


@dataclass
class Alert:
    """A notification dispatched to a human or a channel."""

    target: str
    channel: str
    subject: str
    body: str
    severity: str = "medium"
    id: str = field(default_factory=lambda: new_id("alrt"))
    ts: datetime = field(default_factory=utcnow)
    delivered: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "channel": self.channel,
            "target": self.target,
            "subject": self.subject,
            "severity": self.severity,
            "delivered": self.delivered,
            "ts": self.ts.isoformat(),
        }


@dataclass
class PlaybookRun:
    """One execution of a SOAR playbook against a case or finding."""

    playbook: str
    trigger: dict
    steps: list = field(default_factory=list)
    dry_run: bool = True
    id: str = field(default_factory=lambda: new_id("run"))
    ts: datetime = field(default_factory=utcnow)
    status: str = "completed"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "playbook": self.playbook,
            "dry_run": self.dry_run,
            "status": self.status,
            "trigger": self.trigger,
            "steps": self.steps,
            "ts": self.ts.isoformat(),
        }
