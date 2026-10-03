"""Authentication anomaly watch: catch credential attacks in the logs.

Real-world attack this stops: brute-force attacks hammer one account from one
machine; password-spray attacks try a few common passwords across many
accounts from one machine to dodge lockouts; distributed (low-and-slow)
attacks spread attempts across many IPs so no single source looks abusive.
All three end the same way — a breached account. This engine reads auth log
lines of the form ``ISO8601 ip user result`` (result ``ok``|``fail``) and
flags each pattern with tuned thresholds.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from aegis.engines import register
from aegis.engines.base import Engine, ScanContext
from aegis.models import Finding


def _parse_lines(lines: list[str]) -> list[tuple[datetime, str, str, str]]:
    """Parse ``ISO8601 ip user result`` lines; skip malformed ones."""
    events: list[tuple[datetime, str, str, str]] = []
    for line in lines or []:
        parts = line.split()
        if len(parts) < 4:
            continue
        ts_raw, ip, user, result = parts[0], parts[1], parts[2], parts[3].lower()
        if result not in ("ok", "fail"):
            continue
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        events.append((ts, ip, user, result))
    return events


@register
class AuthWatch(Engine):
    """Detects brute-force, password-spray, and distributed login attacks."""

    name = "auth_watch"
    version = "1.0.0"
    description = (
        "Analyzes auth logs for brute-force (many fails, one IP, short "
        "window), password spray (many users, one IP), and distributed "
        "attacks (one user, many IPs)."
    )

    def scan(self, ctx: ScanContext) -> list[Finding]:
        fail_threshold = int(
            self.opt("fail_threshold", ctx.option("fail_threshold", 8))
        )
        window_minutes = int(
            self.opt("window_minutes", ctx.option("window_minutes", 10))
        )
        spray_users = int(self.opt("spray_users", ctx.option("spray_users", 5)))
        spray_ips = int(self.opt("spray_ips", ctx.option("spray_ips", 5)))

        events = _parse_lines(ctx.data.get("auth_log"))
        fails = [e for e in events if e[3] == "fail"]
        findings: list[Finding] = []

        fails_by_ip: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        users_by_ip: dict[str, set[str]] = defaultdict(set)
        ips_by_user: dict[str, set[str]] = defaultdict(set)
        for ts, ip, user, _ in fails:
            fails_by_ip[ip].append((ts, user))
            users_by_ip[ip].add(user)
            ips_by_user[user].add(ip)

        window = timedelta(minutes=window_minutes)

        # --- brute force: many fails from one IP inside a short window ------
        for ip, attempts in sorted(fails_by_ip.items()):
            times = sorted(ts for ts, _ in attempts)
            peak = 1
            start = 0
            for end in range(len(times)):
                while times[end] - times[start] > window:
                    start += 1
                peak = max(peak, end - start + 1)
            if peak >= fail_threshold:
                findings.append(
                    self.finding(
                        title=f"Brute-force attack from {ip}",
                        score=85,
                        entities={"ip": ip},
                        evidence={
                            "ip": ip,
                            "failures_in_window": peak,
                            "window_minutes": window_minutes,
                            "threshold": fail_threshold,
                            "targeted_users": sorted(users_by_ip[ip]),
                        },
                        recommendation=(
                            f"Block or rate-limit {ip} immediately, force "
                            "password resets on targeted accounts, and check "
                            "for any successful logins from that IP."
                        ),
                        tags=["brute-force", "credential-attack", "auth"],
                    )
                )

        # --- password spray: one IP failing across many distinct users ------
        for ip, users in sorted(users_by_ip.items()):
            if len(users) >= spray_users:
                findings.append(
                    self.finding(
                        title=f"Password-spray attack from {ip}",
                        score=85,
                        entities={"ip": ip},
                        evidence={
                            "ip": ip,
                            "distinct_users": sorted(users),
                            "user_count": len(users),
                            "threshold": spray_users,
                        },
                        recommendation=(
                            f"Block {ip}; it is testing common passwords "
                            "across many accounts to dodge per-account "
                            "lockouts. Review all targeted accounts."
                        ),
                        tags=["password-spray", "credential-attack", "auth"],
                    )
                )

        # --- distributed: one user failing from many distinct IPs -----------
        for user, ips in sorted(ips_by_user.items()):
            if len(ips) >= spray_ips:
                findings.append(
                    self.finding(
                        title=f"Distributed login attack against user '{user}'",
                        score=60,
                        entities={"user": user},
                        evidence={
                            "user": user,
                            "source_ips": sorted(ips),
                            "ip_count": len(ips),
                            "threshold": spray_ips,
                        },
                        recommendation=(
                            f"Account '{user}' is being attacked from many "
                            "IPs (low-and-slow to evade IP blocks). Force a "
                            "password reset, enable MFA, and consider "
                            "geo/velocity rules."
                        ),
                        tags=["distributed-attack", "credential-attack", "auth"],
                    )
                )

        return findings
