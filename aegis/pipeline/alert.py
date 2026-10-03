"""Stage 6 — alert. Route scored findings that cross the alert threshold to
human channels, and build Slack/Discord payloads for them."""

from __future__ import annotations

from typing import Callable

from aegis.config import AegisConfig
from aegis.models import Alert, ScoredFinding

SEVERITY_COLORS = {
    "critical": 0xFF3B30,
    "high": 0xFF9500,
    "medium": 0xFFCC00,
    "low": 0x34C759,
    "informational": 0x8E8E93,
}


def _alert_body(scored: ScoredFinding) -> str:
    """Compact summary + top evidence + recommendation, plain text."""
    f = scored.finding
    lines = [
        f"Aegis detected: {f.title}",
        (
            f"Engine: {f.engine} | Adjusted score: {scored.adjusted_score:.1f}/100 "
            f"({scored.adjusted_severity})"
        ),
    ]
    if f.entities:
        lines.append(
            "Entities: " + ", ".join(f"{k}={v}" for k, v in f.entities.items())
        )
    evidence = list(f.evidence.items())[:3]
    if evidence:
        lines.append("Top evidence:")
        lines.extend(f"  - {k}: {v}" for k, v in evidence)
    if f.recommendation:
        lines.append(f"Recommendation: {f.recommendation}")
    return "\n".join(lines)


def route(
    scored: list[ScoredFinding],
    cfg: AegisConfig,
    send: Callable[[Alert], bool],
) -> list[Alert]:
    """Build an Alert for every finding at/above ``cfg.alert_threshold``,
    hand it to ``send`` (which performs delivery and returns a bool), and
    record the outcome on ``alert.delivered``."""
    channel = getattr(cfg, "alert_channel", "webhook")
    target = getattr(cfg, "alert_target", "security-ops")
    alerts: list[Alert] = []
    for s in scored:
        if s.adjusted_score < cfg.alert_threshold:
            continue
        alert = Alert(
            target=target,
            channel=channel,
            subject=f"[AEGIS] {s.adjusted_severity}: {s.finding.title}",
            body=_alert_body(s),
            severity=s.adjusted_severity,
        )
        alert.delivered = bool(send(alert))
        alerts.append(alert)
    return alerts


def format_slack(scored: ScoredFinding) -> dict:
    """Build a Slack Block Kit payload for a scored finding."""
    f = scored.finding
    entities = ", ".join(f"{k}={v}" for k, v in f.entities.items()) or "none"
    return {
        "text": f"[AEGIS] {scored.adjusted_severity}: {f.title}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"AEGIS {scored.adjusted_severity.upper()}: {f.title}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Engine:*\n{f.engine}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Score:*\n{scored.adjusted_score:.1f}/100",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{scored.adjusted_severity}",
                    },
                    {"type": "mrkdwn", "text": f"*Entities:*\n{entities}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommendation:*\n{f.recommendation or '—'}",
                },
            },
        ],
    }


def format_discord(scored: ScoredFinding) -> dict:
    """Build a Discord webhook payload (embed) for a scored finding."""
    f = scored.finding
    entities = ", ".join(f"{k}={v}" for k, v in f.entities.items()) or "none"
    evidence = "\n".join(f"{k}: {v}" for k, v in list(f.evidence.items())[:3]) or "none"
    return {
        "embeds": [
            {
                "title": f"[AEGIS] {scored.adjusted_severity}: {f.title}",
                "description": (
                    f"Engine `{f.engine}` — adjusted score "
                    f"**{scored.adjusted_score:.1f}/100**"
                ),
                "color": SEVERITY_COLORS.get(scored.adjusted_severity, 0x8E8E93),
                "fields": [
                    {"name": "Entities", "value": entities, "inline": False},
                    {"name": "Top evidence", "value": evidence, "inline": False},
                    {
                        "name": "Recommendation",
                        "value": f.recommendation or "—",
                        "inline": False,
                    },
                ],
                "footer": {"text": "Aegis detection pipeline"},
            }
        ]
    }
