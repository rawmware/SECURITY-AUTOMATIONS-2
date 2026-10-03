"""HTTP routes for the Aegis API."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.api.schemas import (
    AlertOut,
    CaseOut,
    EngineInfo,
    FindingOut,
    PlaybookRunOut,
    ScanRequest,
    ScanResponse,
)
from aegis.engines import engine_names, get_engine, load_engines
from aegis.models import PlaybookRun

log = logging.getLogger("aegis.api")

router = APIRouter()


class SoarRunRequest(BaseModel):
    playbook: str
    trigger: dict = Field(default_factory=dict)
    dry_run: bool = True


# --------------------------------------------------------------------------
# SOAR bridging (defensive: soar package may not be built yet)
# --------------------------------------------------------------------------

def _library_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "soar" / "library"


def _list_playbooks() -> list[str]:
    lib = _library_dir()
    if not lib.is_dir():
        return []
    return sorted(p.stem for p in lib.glob("*.y*ml"))


def _execute_playbook(playbook: str, trigger: dict, dry_run: bool) -> PlaybookRun:
    """Run a playbook through the real PlaybookEngine when available;
    otherwise return a simulated dry run so the endpoint stays functional."""
    try:
        from aegis.soar.engine import PlaybookEngine  # type: ignore
    except ImportError:
        PlaybookEngine = None  # type: ignore

    if PlaybookEngine is None:
        log.info("SOAR engine not installed; simulating playbook %s", playbook)
        return PlaybookRun(
            playbook=playbook,
            trigger=trigger,
            dry_run=True,
            status="simulated",
            steps=[
                {
                    "action": "simulate",
                    "detail": (
                        "aegis.soar.engine.PlaybookEngine is not installed yet; "
                        "no actions were executed."
                    ),
                }
            ],
        )

    engine = PlaybookEngine(library_dir=str(_library_dir()))
    pb = next((p for p in engine.library if p.get("name") == playbook), None)
    if pb is None:
        raise HTTPException(
            status_code=404,
            detail=f"playbook {playbook!r} not found; "
            f"available: {[p.get('name') for p in engine.library]}",
        )
    result = engine.run(pb, trigger=trigger, dry_run=dry_run)
    if isinstance(result, PlaybookRun):
        return result
    # Tolerate engines that return dicts.
    return PlaybookRun(
        playbook=playbook,
        trigger=trigger,
        dry_run=dry_run,
        status=str(getattr(result, "status", "completed")),
        steps=list(getattr(result, "steps", []) or []),
    )


def _ensure_engines_loaded() -> None:
    try:
        load_engines()
    except ImportError:
        pass


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@router.get("/health")
def health() -> dict:
    """Liveness probe: status, version, registered engine count."""
    _ensure_engines_loaded()
    return {
        "status": "ok",
        "version": __version__,
        "engines": len(engine_names()),
    }


@router.get("/engines", response_model=list[EngineInfo])
def list_engines(request: Request) -> list[EngineInfo]:
    """Enumerate the engine fleet with versions, descriptions, toggles."""
    _ensure_engines_loaded()
    config = request.app.state.config
    infos: list[EngineInfo] = []
    for name in engine_names():
        cls = get_engine(name)
        if cls is None:
            continue
        infos.append(
            EngineInfo(
                name=name,
                version=getattr(cls, "version", "0.0.0"),
                description=getattr(cls, "description", "") or "",
                enabled=config.engine_enabled(name),
            )
        )
    return infos


@router.post("/scan", response_model=ScanResponse)
def run_scan(payload: ScanRequest, request: Request) -> ScanResponse:
    """Run the full engine fleet + pipeline; persist results in-memory."""
    runner = request.app.state.runner
    result = runner.run(targets=payload.targets, sim_data=payload.sim_data)

    request.app.state.findings.extend(result["findings"])
    request.app.state.cases.extend(result["cases"])

    return ScanResponse(
        findings=[FindingOut(**f.to_dict()) for f in result["findings"]],
        cases=[CaseOut(**c.to_dict()) for c in result["cases"]],
        engines_run=result["engines_run"],
        errors=result["errors"],
    )


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    request: Request, severity: str | None = None, engine: str | None = None
) -> list[FindingOut]:
    """List stored findings, optionally filtered by severity and/or engine."""
    out: list[FindingOut] = []
    for finding in request.app.state.findings:
        if severity and finding.severity != severity:
            continue
        if engine and finding.engine != engine:
            continue
        out.append(FindingOut(**finding.to_dict()))
    return out


@router.get("/cases", response_model=list[CaseOut])
def list_cases(request: Request) -> list[CaseOut]:
    return [CaseOut(**c.to_dict()) for c in request.app.state.cases]


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: str, request: Request) -> CaseOut:
    for case in request.app.state.cases:
        if case.id == case_id:
            return CaseOut(**case.to_dict())
    raise HTTPException(status_code=404, detail=f"case {case_id!r} not found")


@router.post("/soar/run", response_model=PlaybookRunOut)
def run_playbook(payload: SoarRunRequest, request: Request) -> PlaybookRunOut:
    """Execute (or dry-run) a SOAR playbook from aegis/soar/library."""
    run = _execute_playbook(payload.playbook, payload.trigger, payload.dry_run)
    request.app.state.playbook_runs.append(run)
    return PlaybookRunOut(**run.to_dict())


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(request: Request) -> list[AlertOut]:
    return [AlertOut(**a.to_dict()) for a in request.app.state.alerts]
