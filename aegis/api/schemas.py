"""Pydantic v2 schemas for the Aegis HTTP API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    id: str
    engine: str
    title: str
    severity: str
    score: float
    entities: dict = Field(default_factory=dict)
    evidence: dict = Field(default_factory=dict)
    recommendation: str = ""
    tags: list[str] = Field(default_factory=list)
    ts: str


class ScoredFindingOut(BaseModel):
    id: str
    engine: str
    title: str
    severity: str
    score: float
    adjusted_score: float
    adjusted_severity: str
    score_factors: dict = Field(default_factory=dict)
    entities: dict = Field(default_factory=dict)
    evidence: dict = Field(default_factory=dict)
    recommendation: str = ""
    tags: list[str] = Field(default_factory=list)
    ts: str


class CaseOut(BaseModel):
    id: str
    title: str
    severity: str
    score: float
    status: str
    entities: dict = Field(default_factory=dict)
    narrative: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    ts: str


class AlertOut(BaseModel):
    id: str
    channel: str
    target: str
    subject: str
    severity: str
    delivered: bool
    ts: str


class PlaybookRunOut(BaseModel):
    id: str
    playbook: str
    dry_run: bool
    status: str
    trigger: dict = Field(default_factory=dict)
    steps: list[dict] = Field(default_factory=list)
    ts: str


class ScanRequest(BaseModel):
    targets: dict = Field(default_factory=dict)
    sim_data: dict = Field(default_factory=dict)


class ScanResponse(BaseModel):
    findings: list[FindingOut]
    cases: list[CaseOut]
    engines_run: list[str]
    errors: list[dict] = Field(default_factory=list)


class EngineInfo(BaseModel):
    name: str
    version: str
    description: str
    enabled: bool
