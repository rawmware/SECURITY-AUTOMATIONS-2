"""A tiny in-process event bus. Engines publish findings; pipeline stages
and the API stream subscribe. No broker required for a single node."""

from __future__ import annotations

from collections import defaultdict
from typing import Callable


class Bus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Callable]] = defaultdict(list)

    def subscribe(self, topic: str, fn: Callable) -> Callable:
        """Subscribe ``fn(payload)`` to ``topic``. Returns an unsubscribe fn."""
        self._subs[topic].append(fn)

        def _off() -> None:
            try:
                self._subs[topic].remove(fn)
            except ValueError:
                pass

        return _off

    def publish(self, topic: str, payload) -> int:
        """Deliver payload to every subscriber. Returns deliveries made."""
        delivered = 0
        for fn in list(self._subs.get(topic, ())):
            fn(payload)
            delivered += 1
        return delivered

    def topics(self) -> list[str]:
        return sorted(self._subs.keys())


#: Process-wide default bus, so engines and CLI agree without wiring.
default_bus = Bus()
