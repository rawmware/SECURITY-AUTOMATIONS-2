"""The contract every detection engine implements.

An engine is a pure-ish function: ``scan(ctx) -> list[Finding]``. All I/O —
DNS, HTTP, file reads — goes through the injected ``ScanContext`` hooks so
tests stay hermetic and the demo can simulate the internet.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from aegis.models import Finding, severity_for_score
from aegis.utils import clamp


@dataclass
class ScanContext:
    """Everything an engine may need, injected. Engines must not do raw
    socket/file I/O outside these hooks."""

    targets: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    # --- injectable I/O hooks (overridden in tests / demo) ---
    dns_resolve: Callable[[str, str], list] = field(
        default=lambda host, rtype: []
    )
    http_get: Callable[[str], dict] = field(default=lambda url: {})
    read_file: Callable[[str], str] = field(default=lambda path: "")
    now_iso: Callable[[], str] = field(
        default=lambda: __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat()
    )
    data: dict = field(default_factory=dict)  # scenario/sim inputs

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)


class Engine(ABC):
    """Base class. Subclass, set ``name``/``description``, implement ``scan``,
    decorate with ``@register``."""

    name: str = "base"
    version: str = "1.0.0"
    description: str = ""

    def __init__(self, config: dict | None = None) -> None:
        self.config = dict(config or {})

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[Finding]:
        """Run the detection. Return findings (possibly empty)."""

    # -- helpers ---------------------------------------------------------
    def finding(
        self,
        title: str,
        score: float,
        entities: dict | None = None,
        evidence: dict | None = None,
        recommendation: str = "",
        tags: list | tuple = (),
    ) -> Finding:
        score = clamp(score)
        return Finding(
            engine=self.name,
            title=title,
            severity=severity_for_score(score),
            score=score,
            entities=dict(entities or {}),
            evidence=dict(evidence or {}),
            recommendation=recommendation,
            tags=list(tags),
        )

    def opt(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)
