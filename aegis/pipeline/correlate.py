"""Stage 4 — correlate. Group findings that belong to one attacker campaign
into a single Case, with a plain-English narrative of the attack chain."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from aegis.models import Case, ScoredFinding, severity_for_score

#: Kill-chain stages in attack order, used to order narratives.
KILL_CHAIN_ORDER = (
    "recon",
    "initial access",
    "execution",
    "persistence",
    "privilege escalation",
    "defense evasion",
    "credential access",
    "discovery",
    "lateral movement",
    "collection",
    "exfiltration",
    "impact",
)

#: Which kill-chain stage each detection engine observes.
ENGINE_STAGE = {
    "typo_watch": "recon",
    "dns_sentinel": "recon",
    "auth_watch": "initial access",
    "phish_kit": "initial access",
    "url_intel": "initial access",
    "cve_watch": "initial access",
    "cloud_posture": "initial access",
    "process_guard": "execution",
    "tls_watch": "defense evasion",
    "secret_sentry": "credential access",
    "port_watch": "discovery",
    "egress_watch": "exfiltration",
}

#: Human-readable attack-pattern label per engine, used in case titles.
ENGINE_PATTERN = {
    "auth_watch": "brute-force",
    "typo_watch": "typosquatting",
    "phish_kit": "phishing",
    "url_intel": "malicious URL",
    "secret_sentry": "secret leak",
    "cve_watch": "vulnerability exposure",
    "cloud_posture": "cloud misconfiguration",
    "dns_sentinel": "DNS drift",
    "tls_watch": "TLS misconfig",
    "port_watch": "attack-surface exposure",
    "egress_watch": "exfiltration",
    "process_guard": "suspicious execution",
}

#: Entity keys considered when linking findings; priority for picking the
#: case's primary (named) entity on ties.
_LINK_KEYS = ("ip", "domain", "user", "host")
_ENTITY_PRIORITY = {"host": 0, "user": 1, "ip": 2, "domain": 3}


def chain_stage(finding) -> str:
    """Map a finding's engine to its kill-chain stage (``"unknown"`` when
    the engine isn't in the platform's registry)."""
    engine = getattr(finding, "engine", None)
    return ENGINE_STAGE.get(engine, "unknown")


def _stage_rank(stage: str) -> int:
    try:
        return KILL_CHAIN_ORDER.index(stage)
    except ValueError:
        return len(KILL_CHAIN_ORDER)


def correlate(scored: list[ScoredFinding], window_minutes: int = 60) -> list[Case]:
    """Group scored findings into cases.

    Two findings link when they share at least one entity value (ip, domain,
    user, host) and their timestamps fall inside ``window_minutes`` of each
    other; links are transitive (union-find), so a chain of overlapping
    pairs becomes one case. Singleton findings get their own case.
    """
    items = sorted(scored, key=lambda s: s.finding.ts)
    n = len(items)
    parent = list(range(n))

    def find(a: int) -> int:
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    window = timedelta(minutes=window_minutes)
    for i in range(n):
        for j in range(i + 1, n):
            if items[j].finding.ts - items[i].finding.ts > window:
                break
            ei, ej = items[i].finding.entities, items[j].finding.entities
            if any(
                k in ei and k in ej and str(ei[k]) == str(ej[k])
                for k in _LINK_KEYS
            ):
                union(i, j)

    groups: dict[int, list[ScoredFinding]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(items[i])
    ordered = sorted(
        groups.values(), key=lambda g: min(s.finding.ts for s in g)
    )
    return [_build_case(group) for group in ordered]


def _build_case(group: list[ScoredFinding]) -> Case:
    findings = [s.finding for s in group]
    scores = [s.adjusted_score for s in group]
    score = min(100.0, max(scores) + 5 * (len(group) - 1))
    score = round(score, 1)

    engine_counts = Counter(f.engine for f in findings)
    dominant = engine_counts.most_common(1)[0][0]
    pattern = ENGINE_PATTERN.get(dominant, "security incident")
    primary_key, primary_value = _primary_entity(group)
    plural = "s" if len(group) != 1 else ""
    title = f"Coordinated {pattern} against {primary_value} ({len(group)} finding{plural})"

    entities: dict = {}
    for f in findings:
        for k, v in f.entities.items():
            entities.setdefault(k, v)

    narrative = _narrative(group, primary_value)

    return Case(
        title=title,
        findings=findings,
        severity=severity_for_score(score),
        score=score,
        entities=entities,
        narrative=narrative,
    )


def _primary_entity(group: list[ScoredFinding]) -> tuple[str, str]:
    """Pick the entity value that best names the case: most frequent, with
    host > user > ip > domain on ties."""
    counts: Counter[tuple[str, str]] = Counter()
    for s in group:
        for key in _LINK_KEYS:
            value = s.finding.entities.get(key)
            if value is not None:
                counts[(key, str(value))] += 1
    if not counts:
        return ("entity", "unknown target")
    (key, value), _ = sorted(
        counts.items(),
        key=lambda kv: (-kv[1], _ENTITY_PRIORITY.get(kv[0][0], 9), kv[0][1]),
    )[0]
    return key, value


def _narrative(group: list[ScoredFinding], primary_value: str) -> str:
    """2–3 sentence plain-English summary naming entities and the kill-chain
    progression."""
    n = len(group)
    plural = "s" if n != 1 else ""
    first = (
        f"Aegis correlated {n} finding{plural} against {primary_value}, "
        "likely from a single coordinated attack."
    )

    stage_engines: dict[str, list[str]] = {}
    for s in group:
        stage = chain_stage(s.finding)
        stage_engines.setdefault(stage, [])
        if s.finding.engine not in stage_engines[stage]:
            stage_engines[stage].append(s.finding.engine)
    ordered_stages = sorted(stage_engines, key=_stage_rank)
    if len(ordered_stages) > 1:
        legs = [
            f"{stage} ({', '.join(stage_engines[stage])})"
            for stage in ordered_stages
        ]
        second = "The attack chain moved from " + " to ".join(legs) + "."
    else:
        stage = ordered_stages[0]
        second = (
            f"All activity sits at the {stage} stage "
            f"({', '.join(stage_engines[stage])})."
        )

    shared: Counter[str] = Counter()
    for s in group:
        seen = set()
        for key in _LINK_KEYS:
            value = s.finding.entities.get(key)
            if value is not None:
                seen.add(f"{key}={value}")
        for marker in seen:
            shared[marker] += 1
    repeated = sorted(
        ((m, c) for m, c in shared.items() if c >= 2),
        key=lambda mc: (-mc[1], mc[0]),
    )[:3]
    if repeated:
        tail = "Shared indicators: " + ", ".join(
            f"{marker} in {count}/{n} findings" for marker, count in repeated
        ) + "."
        return " ".join([first, second, tail])
    return " ".join([first, second])
