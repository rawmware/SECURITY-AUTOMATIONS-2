"""Secret Sentry — leaked-credential scanning across code, configs, and logs.

The real attack: developers hardcode AWS keys, GitHub tokens, and API secrets
into source, config files, and chat logs. One ``git push`` or one leaked repo
and an attacker running automated secret scanners (GitHub's own secret
scanning, gitleaks, trufflehog) holds infrastructure credentials — often
within minutes, while the owner thinks nothing happened. This engine scans
free text with a battery of high-signal patterns plus a Shannon-entropy gate
on generic ``key=value`` pairs, so ``password=changeme123`` never pages
anyone at 3am. Findings never carry the raw secret — only a redacted preview.
"""

from __future__ import annotations

import re

from aegis.engines import Engine, register
from aegis.engines.base import ScanContext
from aegis.utils import sha256_short, shannon_entropy

# (finding key, compiled pattern, score, group holding the secret value)
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET_TOKEN_RE = re.compile(r"[A-Za-z0-9/+=]{40}")
GITHUB_PAT_RE = re.compile(r"(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")
GENERIC_RE = re.compile(
    r"(?i)(api_key|apikey|secret|token|passwd|password)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-+/=]{16,})['\"]?"
)

#: Shannon entropy floor (bits/char) for generic key=value matches.
#: English prose sits ~3.5-4.5; random tokens land ~4.5-6.0.
ENTROPY_FLOOR = 4.2

#: Characters of context searched on each side of a 40-char token for an
#: ``aws_secret`` label.
LABEL_WINDOW = 100


def _redact(secret: str) -> str:
    """First 4 characters plus ellipsis — enough to recognize, never enough
    to use."""
    return secret[:4] + "…"


def _allowlisted(secret: str, text: str, allowlist: list) -> bool:
    return any(s and (s in secret or s in text) for s in allowlist)


@register
class SecretSentry(Engine):
    """Scans text sources for leaked credentials."""

    name = "secret_sentry"
    version = "1.0.0"
    description = (
        "Detects leaked secrets (cloud keys, PATs, private keys, API "
        "tokens) in text via high-signal patterns plus an entropy gate."
    )

    def scan(self, ctx: ScanContext) -> list:
        texts: dict = ctx.data.get("texts") or {}
        allowlist: list = ctx.option("allowlist", []) or []
        seen: set[str] = set()
        findings: list = []

        for source, text in texts.items():
            text = text or ""
            for title, secret, score, pattern in self._scan_text(text):
                digest = sha256_short(secret)
                if digest in seen or _allowlisted(secret, text, allowlist):
                    continue
                seen.add(digest)
                findings.append(
                    self.finding(
                        title=f"{title} in {source}",
                        score=score,
                        entities={"source": source, "secret_type": pattern},
                        evidence={
                            "pattern": pattern,
                            "preview": _redact(secret),
                            "sha": digest,
                        },
                        recommendation=(
                            "Revoke the credential immediately, rotate any "
                            "dependent secrets, and check audit logs for use "
                            f"of the key (sha {digest})."
                        ),
                        tags=["credential", "leak", pattern],
                    )
                )
        return findings

    # -- pattern passes ---------------------------------------------------
    def _scan_text(self, text: str):
        """Yield (title, secret, score, pattern-name) for every match."""
        for match in AWS_KEY_RE.finditer(text):
            yield ("AWS access key exposed", match.group(0), 90, "aws_access_key")
        for title, secret in self._aws_secrets(text):
            yield (title, secret, 90, "aws_secret")
        for match in GITHUB_PAT_RE.finditer(text):
            yield ("GitHub token exposed", match.group(0), 85, "github_pat")
        for match in PRIVATE_KEY_RE.finditer(text):
            yield ("Private key material exposed", match.group(0), 95, "private_key")
        for match in GENERIC_RE.finditer(text):
            value = match.group(2)
            if shannon_entropy(value) >= ENTROPY_FLOOR:
                yield ("Hardcoded credential exposed", value, 70, "generic")

    def _aws_secrets(self, text: str):
        """40-char base64-ish tokens count as AWS secret keys only when the
        ``aws_secret`` label appears nearby — bare 40-char strings are too
        noisy on their own."""
        lowered = text.lower()
        for match in AWS_SECRET_TOKEN_RE.finditer(text):
            start, end = match.span()
            window = lowered[max(0, start - LABEL_WINDOW) : end + LABEL_WINDOW]
            if "aws_secret" in window:
                yield ("AWS secret key exposed", match.group(0))
