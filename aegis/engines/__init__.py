"""Engine registry. Every engine module registers itself here so the
orchestrator, API, and CLI can enumerate the fleet without imports."""

from __future__ import annotations

from aegis.engines.base import Engine

_REGISTRY: dict[str, type[Engine]] = {}


def register(engine_cls: type[Engine]) -> type[Engine]:
    _REGISTRY[engine_cls.name] = engine_cls
    return engine_cls


def engine_names() -> list[str]:
    return sorted(_REGISTRY.keys())


def get_engine(name: str) -> type[Engine] | None:
    return _REGISTRY.get(name)


def load_engines() -> None:
    """Import every engine module so @register decorators fire."""
    import importlib

    for mod in (
        "aegis.engines.typo_watch",
        "aegis.engines.dns_sentinel",
        "aegis.engines.tls_watch",
        "aegis.engines.port_watch",
        "aegis.engines.auth_watch",
        "aegis.engines.url_intel",
        "aegis.engines.secret_sentry",
        "aegis.engines.cve_watch",
        "aegis.engines.cloud_posture",
        "aegis.engines.phish_kit",
        "aegis.engines.anomaly_mind",
        "aegis.engines.canary_trip",
    ):
        importlib.import_module(mod)


__all__ = ["Engine", "register", "engine_names", "get_engine", "load_engines"]
