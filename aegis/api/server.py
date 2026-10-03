"""Aegis HTTP API: FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from aegis import __version__
from aegis.api.routes import router
from aegis.api.stream import ws_router
from aegis.bus import Bus
from aegis.config import AegisConfig
from aegis.engines import load_engines
from aegis.runner import ScanRunner


@asynccontextmanager
async def _lifespan(app: FastAPI):
    try:
        load_engines()
    except ImportError:
        # Engine modules may not be installed yet (parallel build / tests).
        pass
    yield


def create_app(config: AegisConfig | None = None) -> FastAPI:
    """Build the Aegis FastAPI application.

    ``app.state`` carries: ``config``, ``runner``, ``bus``, and the
    in-memory stores ``findings``, ``cases``, ``alerts``, ``playbook_runs``.
    """
    config = config or AegisConfig()
    bus = Bus()

    app = FastAPI(title="Aegis API", version=__version__, lifespan=_lifespan)
    app.state.config = config
    app.state.bus = bus
    app.state.runner = ScanRunner(config, bus=bus)
    app.state.findings = []
    app.state.cases = []
    app.state.alerts = []
    app.state.playbook_runs = []

    app.include_router(router)
    app.include_router(ws_router)
    return app
