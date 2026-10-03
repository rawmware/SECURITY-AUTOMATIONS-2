"""Phish Kit — phishing-kit fingerprinting of web pages.

The real attack: credential-phishing kits are sold as plug-and-play zip
files. An attacker unzips one, clones your bank's login page, and starts
harvesting passwords — exfiltrating them to a Telegram bot or a throwaway
drop server. Kits leave fingerprints: password-harvesting forms, Telegram
exfil endpoints, obfuscated JavaScript, hidden iframes, and brand-bait
phrasing like "verify your account". This engine scores pages by weighted
marker matches, so a legitimate login page (one or two markers) doesn't
trigger while an actual kit (many markers stacked) does.
"""

from __future__ import annotations

import re

from aegis.engines import Engine, register
from aegis.engines.base import ScanContext

DEFAULT_MIN_SCORE = 35

#: (marker name, regex, weight). Weights sum toward a 0-100 page score.
STATIC_MARKERS: list[tuple[str, str, int]] = [
    ("credential_harvester", r'<input[^>]*type="password"', 30),
    ("telegram_exfil", r"api\.telegram\.org/bot", 40),
    ("obfuscated_js", r"eval\(unescape\(", 25),
    ("hidden_iframe", r"<iframe[^>]*display:\s*none", 20),
    ("brand_impersonation", r"(?i)(verify|confirm).{0,20}(account|identity)", 15),
]


def _form_post_marker(brand: str) -> tuple[str, str, int]:
    """External form-post marker. A login form posting to a foreign domain
    is the kit's whole business model; the brand's own domain (and its
    subdomains) are excluded."""
    if brand:
        pattern = (
            r'<form[^>]*action="https?://(?!(?:[\w-]+\.)*'
            + re.escape(brand)
            + r'(?:[/?#"]|$))'
        )
    else:
        pattern = r'<form[^>]*action="https?://(?!example)'
    return ("external_form_post", pattern, 25)


@register
class PhishKit(Engine):
    """Fingerprints phishing kits in page HTML via weighted markers."""

    name = "phish_kit"
    version = "1.0.0"
    description = (
        "Scores web pages against known phishing-kit fingerprints "
        "(credential harvesters, Telegram exfil, obfuscated JS, hidden "
        "iframes, brand impersonation, external form posts)."
    )

    def scan(self, ctx: ScanContext) -> list:
        pages: dict = ctx.data.get("pages") or {}
        min_score: float = float(ctx.option("min_score", DEFAULT_MIN_SCORE))
        brand: str = str(ctx.targets.get("domain", "") or "")
        markers = list(STATIC_MARKERS)
        markers.append(_form_post_marker(brand))
        compiled = [
            (name, re.compile(rx, re.IGNORECASE | re.DOTALL), weight)
            for name, rx, weight in markers
        ]

        findings: list = []
        for url, html in pages.items():
            html = html or ""
            matched = [name for name, rx, _ in compiled if rx.search(html)]
            if not matched:
                continue
            weights = {name: weight for name, _, weight in compiled}
            total = min(100, sum(weights[name] for name in matched))
            if total < min_score:
                continue
            findings.append(
                self.finding(
                    title=f"Phishing-kit indicators on {url}",
                    score=total,
                    entities={"url": url},
                    evidence={
                        "matched_markers": matched,
                        "marker_weights": {name: weights[name] for name in matched},
                        "min_score": min_score,
                    },
                    recommendation=(
                        f"Take {url} down and preserve it for forensics. "
                        "Extract the exfil destination (e.g. Telegram bot "
                        "token) and search mail gateways / proxy logs for "
                        "victims who visited it."
                    ),
                    tags=["phishing", "web"] + matched,
                )
            )
        return findings
