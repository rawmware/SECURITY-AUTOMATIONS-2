"""ScanRunner: orchestration core of Aegis.

Loads the registered engine fleet, builds an injected :class:`ScanContext`
for each scan, runs every enabled engine, and pushes the raw findings through
the pipeline stages (dedupe → enrich → score → correlate).

Engine failures are isolated per-engine and recorded — one bad engine never
kills a scan. (``pipeline.normalize`` is intentionally bypassed here:
engines emit canonical :class:`Finding` objects already; normalize exists
for raw external telemetry.)
"""

from __future__ import annotations

import logging
import traceback
from typing import Any

from aegis.bus import Bus, default_bus
from aegis.config import AegisConfig
from aegis.engines import engine_names, get_engine, load_engines
from aegis.engines.base import ScanContext
from aegis.models import Case, Finding, ScoredFinding
from aegis.pipeline.correlate import correlate
from aegis.pipeline.dedupe import Deduper
from aegis.pipeline.enrich import enrich
from aegis.pipeline.score import score_finding

log = logging.getLogger("aegis.runner")

class ScanRunner:
    """Run the engine fleet against a target set and return pipeline results."""

    def __init__(self, config: AegisConfig, bus: Bus | None = None) -> None:
        self.config = config
        self.bus = bus or default_bus

    # -- context -----------------------------------------------------------
    def build_context(
        self,
        targets: dict | None = None,
        sim_data: dict | None = None,
    ) -> ScanContext:
        """Build the injected ScanContext.

        Targets merge in order: config defaults (brand_domain) ← provided
        targets. ``sim_data`` is merged into ``ctx.data`` so engines (and
        tests) can inject scenario inputs.
        """
        merged_targets: dict = {"brand_domain": self.config.brand_domain}
        merged_targets.update(targets or {})
        ctx = ScanContext(targets=merged_targets)
        ctx.data.update(sim_data or {})
        return ctx

    # -- engine lifecycle --------------------------------------------------
    def _load_fleet(self) -> list[tuple[str, Any]]:
        """Import engine modules, instantiate enabled engines.

        Returns ``[(name, engine_instance), ...]``.
        """
        load_engines()

        fleet: list[tuple[str, Any]] = []
        for name in engine_names():
            if not self.config.engine_enabled(name):
                continue
            engine_cls = get_engine(name)
            if engine_cls is None:
                continue
            try:
                fleet.append((name, engine_cls(self.config.engine_options(name))))
            except Exception:
                log.warning("engine %s failed to instantiate", name, exc_info=True)
        return fleet

    # -- main run ----------------------------------------------------------
    def run(
        self,
        targets: dict | None = None,
        sim_data: dict | None = None,
    ) -> dict:
        """Execute a full scan. Returns a result dict with keys:

        - ``findings``: raw :class:`Finding` objects from engines
        - ``scored``: :class:`ScoredFinding` objects (post enrich+score+dedupe)
        - ``cases``: :class:`Case` objects from correlation
        - ``engines_run``: names of engines that executed
        - ``errors``: ``[{engine, error}]`` for engines that raised
        """
        ctx = self.build_context(targets, sim_data)
        findings: list[Finding] = []
        errors: list[dict] = []
        engines_run: list[str] = []

        for name, engine in self._load_fleet():
            engines_run.append(name)
            # Per-engine tuning: engines may read ctx.option(...), so expose
            # this engine's config block for the duration of its scan.
            ctx.options = self.config.engine_options(name)
            try:
                produced = engine.scan(ctx) or []
            except Exception as exc:  # noqa: BLE001 - isolate per engine
                errors.append(
                    {
                        "engine": name,
                        "error": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc(limit=5),
                    }
                )
                log.warning("engine %s raised; continuing", name, exc_info=True)
                continue
            for finding in produced:
                findings.append(finding)
                self.bus.publish("findings", finding)

        deduper = Deduper()
        assets = ctx.data.get("assets") or {}
        confidence = float(ctx.option("confidence", 0.85))
        scored: list[ScoredFinding] = []
        for finding in findings:
            try:
                if deduper.is_duplicate(finding):
                    continue
                enrichment = enrich(finding, assets)
                scored.append(score_finding(finding, enrichment, confidence))
            except Exception as exc:  # noqa: BLE001 - pipeline must not die
                errors.append(
                    {
                        "engine": f"pipeline:{finding.engine}",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

        try:
            cases = correlate(scored)
        except Exception as exc:  # noqa: BLE001
            errors.append({"engine": "pipeline:correlate",
                           "error": f"{type(exc).__name__}: {exc}"})
            cases = []

        return {
            "findings": findings,
            "scored": scored,
            "cases": cases,
            "engines_run": engines_run,
            "errors": errors,
        }
