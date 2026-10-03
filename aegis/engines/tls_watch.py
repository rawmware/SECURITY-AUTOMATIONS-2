"""TLS certificate watch: stop outages and downgrade attacks before they bite.

Real-world attack this stops: expired certificates cause hard outages and
browser trust errors that cost revenue and credibility; weak signature
algorithms (SHA-1/MD5) and short keys (1024-bit RSA) let attackers forge or
crack certificates and run man-in-the-middle attacks; a SAN mismatch means
the cert doesn't cover the hostname it serves, breaking trust and hinting at
mis-issuance. This engine scores every known certificate against expiry,
algorithm, key-size, and hostname-coverage rules.
"""

from __future__ import annotations

from datetime import datetime

from aegis.engines import register
from aegis.engines.base import Engine, ScanContext
from aegis.models import Finding

_WEAK_SIG_TOKENS = ("sha1", "md5")
_MIN_KEY_BITS = 2048


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@register
class TlsWatch(Engine):
    """Scores certificates on expiry, signature algorithm, key size, and SAN."""

    name = "tls_watch"
    version = "1.0.0"
    description = (
        "Evaluates known TLS certificates: expiring soon, weak signature "
        "algorithms (SHA-1/MD5), undersized keys, and SAN/hostname mismatch."
    )

    def scan(self, ctx: ScanContext) -> list[Finding]:
        certs = ctx.data.get("tls_certs") or []
        try:
            now = _parse_iso(ctx.now_iso())
        except ValueError:
            now = datetime.now().astimezone()
        findings: list[Finding] = []

        for cert in certs:
            host = cert.get("host", "?")
            entities = {"host": host}

            # --- expiry ----------------------------------------------------
            not_after_raw = cert.get("not_after")
            if not_after_raw:
                try:
                    not_after = _parse_iso(not_after_raw)
                except ValueError:
                    not_after = None
                if not_after is not None:
                    days = (not_after - now).total_seconds() / 86400.0
                    if days < 14:
                        findings.append(
                            self.finding(
                                title=f"Certificate expiring imminently: {host}",
                                score=95,
                                entities=entities,
                                evidence={
                                    "host": host,
                                    "not_after": not_after_raw,
                                    "days_remaining": round(days, 2),
                                },
                                recommendation=(
                                    f"Renew the certificate for {host} "
                                    "immediately — expiry causes browser trust "
                                    "errors and downtime."
                                ),
                                tags=["tls", "expiry", "availability"],
                            )
                        )
                    elif days < 30:
                        findings.append(
                            self.finding(
                                title=f"Certificate expiring within 30 days: {host}",
                                score=80,
                                entities=entities,
                                evidence={
                                    "host": host,
                                    "not_after": not_after_raw,
                                    "days_remaining": round(days, 2),
                                },
                                recommendation=(
                                    f"Schedule renewal for {host}; automate it "
                                    "if possible."
                                ),
                                tags=["tls", "expiry"],
                            )
                        )
                    elif days < 60:
                        findings.append(
                            self.finding(
                                title=f"Certificate expiring within 60 days: {host}",
                                score=55,
                                entities=entities,
                                evidence={
                                    "host": host,
                                    "not_after": not_after_raw,
                                    "days_remaining": round(days, 2),
                                },
                                recommendation=(
                                    f"Put {host} on the renewal calendar."
                                ),
                                tags=["tls", "expiry"],
                            )
                        )

            # --- weak signature algorithm ----------------------------------
            sig_alg = str(cert.get("sig_alg", "") or "").lower()
            if any(tok in sig_alg for tok in _WEAK_SIG_TOKENS):
                findings.append(
                    self.finding(
                        title=f"Weak certificate signature algorithm on {host}",
                        score=75,
                        entities=entities,
                        evidence={"host": host, "sig_alg": cert.get("sig_alg")},
                        recommendation=(
                            f"Reissue the {host} certificate with SHA-256 or "
                            "better; SHA-1/MD5 signatures are forgeable."
                        ),
                        tags=["tls", "weak-crypto"],
                    )
                )

            # --- undersized key --------------------------------------------
            key_bits = cert.get("key_bits")
            if key_bits is not None and int(key_bits) < _MIN_KEY_BITS:
                findings.append(
                    self.finding(
                        title=f"Undersized certificate key on {host}",
                        score=70,
                        entities=entities,
                        evidence={"host": host, "key_bits": int(key_bits)},
                        recommendation=(
                            f"Reissue with at least {_MIN_KEY_BITS}-bit RSA "
                            "(or ECDSA P-256); smaller keys are crackable."
                        ),
                        tags=["tls", "weak-crypto"],
                    )
                )

            # --- SAN / hostname mismatch -----------------------------------
            if not cert.get("san_ok", True):
                findings.append(
                    self.finding(
                        title=f"Certificate hostname mismatch on {host}",
                        score=50,
                        entities=entities,
                        evidence={"host": host, "san_ok": False},
                        recommendation=(
                            f"The certificate served by {host} does not cover "
                            "its hostname. Reissue with the correct SANs."
                        ),
                        tags=["tls", "misconfiguration"],
                    )
                )

        return findings
