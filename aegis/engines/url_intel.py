"""URL threat intel: score links before anyone clicks them.

Real-world attack this stops: phishing links are the #1 initial-access
vector. Attackers hide behind URL shorteners (to mask the destination),
punycode/IDN tricks (``xn--`` domains that render as lookalikes), raw IP
hosts, ``@``-injection (``https://bank.com@evil.top``), shady TLDs, and
overlong query strings stuffing tokens and redirect chains. This engine
unshortens each URL via the injected HTTP hook, applies a transparent
heuristic breakdown, and flags anything scoring at or above the threshold.
"""

from __future__ import annotations

from urllib.parse import urlparse

from aegis.engines import register
from aegis.engines.base import Engine, ScanContext
from aegis.models import Finding
from aegis.utils import looks_like_ip

_SHADY_TLDS = {"top", "xyz", "click", "zip", "mov", "country"}
_KEYWORDS = ("login", "verify", "wallet", "invoice", "urgent")


def _score_url(url: str, redirects: list) -> tuple[float, dict[str, float]]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    query = parsed.query
    lowered = url.lower()
    breakdown: dict[str, float] = {}

    if "xn--" in host:
        breakdown["punycode_idn"] = 25
    if looks_like_ip(host):
        breakdown["ip_host"] = 30
    if "@" in netloc:
        breakdown["at_in_netloc"] = 20
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _SHADY_TLDS:
        breakdown["shady_tld"] = 15
    if len(query) > 120:
        breakdown["long_query"] = 10
    kw_hits = [kw for kw in _KEYWORDS if kw in lowered]
    if kw_hits:
        breakdown["phish_keywords"] = min(20, 10 * len(kw_hits))
    if len(redirects) >= 2:
        breakdown["redirect_chain"] = 15
    if len(url) > 200:
        breakdown["excessive_length"] = 10

    score = min(100.0, float(sum(breakdown.values())))
    return score, breakdown


@register
class UrlIntel(Engine):
    """Unshortens and heuristically scores URLs for phishing indicators."""

    name = "url_intel"
    version = "1.0.0"
    description = (
        "Follows redirect chains and scores URLs on punycode, IP hosts, "
        "@-injection, shady TLDs, phishing keywords, redirect depth, and "
        "length. Flags URLs at or above the score threshold."
    )

    def scan(self, ctx: ScanContext) -> list[Finding]:
        min_score = float(self.opt("min_score", ctx.option("min_score", 40)))
        urls = ctx.data.get("urls") or []
        findings: list[Finding] = []

        for url in urls:
            try:
                response = ctx.http_get(url) or {}
            except Exception:
                response = {}
            redirects = response.get("redirects", []) or []
            if not isinstance(redirects, list):
                redirects = []
            final_url = redirects[-1] if redirects else url

            score, breakdown = _score_url(url, redirects)
            if score < min_score:
                continue

            host = (urlparse(url).hostname or "").lower()
            findings.append(
                self.finding(
                    title=f"Suspicious URL: {url[:80]}",
                    score=score,
                    entities={"url": url, "host": host, "final_url": final_url},
                    evidence={
                        "url": url,
                        "final_url": final_url,
                        "redirects": list(redirects),
                        "redirect_hops": len(redirects),
                        "score_breakdown": breakdown,
                    },
                    recommendation=(
                        "Do not click. Quarantine the message, verify the "
                        "sender through a separate channel, and submit the "
                        "URL to the phishing triage queue."
                    ),
                    tags=["phishing", "url-intel", "initial-access"],
                )
            )
        return findings
