"""Stage 1 — normalize. Coerce arbitrary raw telemetry into the pipeline's
canonical event shape: ``{ts, source, kind, entities, raw}``."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from aegis.utils import utcnow

#: Raw-telemetry keys tried (in order) for each canonical field.
_TS_KEYS = ("ts", "timestamp", "time", "observed_at")
_SOURCE_KEYS = ("source", "src", "origin", "sensor")
_KIND_KEYS = ("kind", "type", "event_type", "event")


def _coerce_ts(value: Any) -> datetime:
    """Best-effort conversion to an aware datetime; ``None`` → now."""
    if value is None:
        return utcnow()
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return utcnow()
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return utcnow()


def _first(raw: dict, keys: tuple[str, ...], default: Any = None) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return default


def normalize_event(raw: dict) -> dict:
    """Coerce arbitrary raw telemetry into the canonical event dict.

    Missing ``ts`` is filled with the current time, ``kind`` is lowercased,
    and ``entities`` is guaranteed to be a dict. The untouched original is
    kept under ``raw`` for auditability.
    """
    raw = dict(raw or {})
    entities = _first(raw, ("entities",), default={})
    if not isinstance(entities, dict):
        entities = {"value": entities}
    return {
        "ts": _coerce_ts(_first(raw, _TS_KEYS)),
        "source": str(_first(raw, _SOURCE_KEYS, default="unknown")),
        "kind": str(_first(raw, _KIND_KEYS, default="")).lower(),
        "entities": entities,
        "raw": raw,
    }
