"""SOAR actions: the verbs playbooks can execute.

Every action returns ``{action, params, result, dry_run}`` and appends a
record to the module-level ``AUDIT_LOG`` — every automated response is
traceable. In dry-run mode nothing external happens; ``result`` just
describes what *would* execute.
"""

from __future__ import annotations

from typing import Any, Callable

from aegis.models import SEVERITIES
from aegis.utils import looks_like_ip, utcnow

#: Append-only record of every action invocation, for forensics and tests.
AUDIT_LOG: list[dict] = []


def get_audit_log() -> list[dict]:
    """Return a snapshot of the audit log."""
    return list(AUDIT_LOG)


def _audit(action: str, params: dict, result: str, dry_run: bool) -> None:
    AUDIT_LOG.append(
        {
            "action": action,
            "params": dict(params),
            "result": result,
            "dry_run": dry_run,
            "ts": utcnow().isoformat(),
        }
    )


def _finish(action: str, params: dict, dry_run: bool, description: str) -> dict:
    result = (
        f"would execute: {description}"
        if dry_run
        else f"executed: {description} (simulated)"
    )
    _audit(action, params, result, dry_run)
    return {"action": action, "params": dict(params), "result": result, "dry_run": dry_run}


def _require_str(name: str, value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} requires a non-empty {label}")
    return value


def block_ip(ip: str, duration: str = "24h", *, dry_run: bool = True) -> dict:
    """Block an IPv4 address at the edge firewall for ``duration``."""
    if not isinstance(ip, str) or not looks_like_ip(ip):
        raise ValueError(f"block_ip requires a valid IPv4 address, got {ip!r}")
    params = {"ip": ip, "duration": duration}
    return _finish("block_ip", params, dry_run, f"block {ip} for {duration}")


def isolate_host(host: str, *, dry_run: bool = True) -> dict:
    """Quarantine a host from the network (EDR network isolation)."""
    host = _require_str("isolate_host", host, "hostname")
    params = {"host": host}
    return _finish("isolate_host", params, dry_run, f"isolate host {host}")


def revoke_token(token_id: str, *, dry_run: bool = True) -> dict:
    """Revoke an exposed API token / credential immediately."""
    token_id = _require_str("revoke_token", token_id, "token id")
    params = {"token_id": token_id}
    return _finish("revoke_token", params, dry_run, f"revoke token {token_id}")


def disable_user(user: str, *, dry_run: bool = True) -> dict:
    """Disable a user account pending investigation."""
    user = _require_str("disable_user", user, "username")
    params = {"user": user}
    return _finish("disable_user", params, dry_run, f"disable user {user}")


def open_case(title: str, severity: str = "medium", *, dry_run: bool = True) -> dict:
    """Open an investigation case for the SOC queue."""
    title = _require_str("open_case", title, "case title")
    if severity not in SEVERITIES:
        raise ValueError(f"open_case got unknown severity: {severity!r}")
    params = {"title": title, "severity": severity}
    return _finish("open_case", params, dry_run, f"open {severity} case: {title}")


def notify(channel: str, message: str, *, dry_run: bool = True) -> dict:
    """Send a message to a notification channel (chat, email, webhook)."""
    channel = _require_str("notify", channel, "channel")
    message = _require_str("notify", message, "message")
    params = {"channel": channel, "message": message}
    return _finish("notify", params, dry_run, f"notify #{channel}: {message}")


def create_ticket(system: str, title: str, *, dry_run: bool = True) -> dict:
    """Create a ticket in an external system (jira, registrar abuse desk…)."""
    system = _require_str("create_ticket", system, "ticketing system")
    title = _require_str("create_ticket", title, "ticket title")
    params = {"system": system, "title": title}
    return _finish("create_ticket", params, dry_run, f"ticket in {system}: {title}")


#: Registry of every executable action, keyed by the name playbooks use.
ACTIONS: dict[str, Callable[..., dict]] = {
    "block_ip": block_ip,
    "isolate_host": isolate_host,
    "revoke_token": revoke_token,
    "disable_user": disable_user,
    "open_case": open_case,
    "notify": notify,
    "create_ticket": create_ticket,
}
