"""Small, dependency-free helpers used across engines and pipeline."""

from __future__ import annotations

import hashlib
import math
import secrets
from collections import Counter
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    """Short, unique, human-scannable id: ``fnd-9f3k2q8x``."""
    return f"{prefix}-{secrets.token_hex(4)}"


def sha256_short(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character. Random tokens score high
    (~4.5–6.0); English prose sits around ~3.5–4.5."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
