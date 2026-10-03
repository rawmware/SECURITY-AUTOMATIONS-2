"""Detection pipeline: normalize → enrich → score → correlate → dedupe →
alert. Each stage is a pure-ish function; see the stage modules for
details."""

from aegis.pipeline.alert import format_discord, format_slack, route
from aegis.pipeline.correlate import KILL_CHAIN_ORDER, chain_stage, correlate
from aegis.pipeline.dedupe import Deduper
from aegis.pipeline.enrich import enrich
from aegis.pipeline.normalize import normalize_event
from aegis.pipeline.score import score_finding

__all__ = [
    "normalize_event",
    "enrich",
    "score_finding",
    "correlate",
    "chain_stage",
    "KILL_CHAIN_ORDER",
    "Deduper",
    "route",
    "format_slack",
    "format_discord",
]
