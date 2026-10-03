"""Stage 5 — dedupe. Suppress repeat firings of the same detection inside a
time window so one noisy rule can't page the SOC fifty times."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from aegis.models import Finding
from aegis.utils import utcnow


class Deduper:
    """Fingerprint-based duplicate suppression with a sliding time window.

    The fingerprint is ``sha256(engine + '|' + title + '|' + sorted entity
    k=v pairs)``. ``seen()`` returns True when the fingerprint was already
    observed inside the window (and refreshes nothing — the original
    timestamp stands); fingerprints older than the window expire.
    """

    def __init__(self, window_minutes: float = 60.0) -> None:
        self.window_minutes = float(window_minutes)
        self._seen: dict[str, datetime] = {}

    def fingerprint(self, finding: Finding) -> str:
        entities = "|".join(
            f"{k}={v}" for k, v in sorted(finding.entities.items())
        )
        material = f"{finding.engine}|{finding.title}|{entities}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(minutes=self.window_minutes)
        self._seen = {fp: ts for fp, ts in self._seen.items() if ts > cutoff}

    def seen(self, fp: str, now: datetime | None = None) -> bool:
        """Record ``fp``; return True if it was already seen inside the
        window (i.e. this event is a duplicate)."""
        now = now or utcnow()
        self._prune(now)
        if fp in self._seen:
            return True
        self._seen[fp] = now
        return False

    def is_duplicate(self, finding: Finding) -> bool:
        """True when this exact detection already fired inside the window."""
        return self.seen(self.fingerprint(finding))

    def reset(self) -> None:
        """Forget all fingerprints (tests, pipeline restarts)."""
        self._seen.clear()
