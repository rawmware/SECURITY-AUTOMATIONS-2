"""Typo-squatting watch: catch lookalike domains before attackers use them.

Real-world attack this stops: phishing and credential theft via domains that
visually mimic your brand (``paypa1.com``, ``login-paypal.com``). Attackers
register typo variants, stand up pixel-perfect login pages, and harvest
credentials from your customers and employees. This engine proactively
generates the most likely typo variants of the brand domain using 12
squatting techniques, then checks DNS and certificate-transparency signals
to see which variants are actually registered and weaponized.
"""

from __future__ import annotations

import re
import string

from aegis.engines import register
from aegis.engines.base import Engine, ScanContext
from aegis.models import Finding

# --- keyboard adjacency for substitution typos --------------------------------
_ADJACENCY: dict[str, list[str]] = {}
_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
for _r, _row in enumerate(_ROWS):
    for _i, _ch in enumerate(_row):
        _nb: set[str] = set()
        if _i > 0:
            _nb.add(_row[_i - 1])
        if _i < len(_row) - 1:
            _nb.add(_row[_i + 1])
        if _r > 0 and _i < len(_ROWS[_r - 1]):
            _nb.add(_ROWS[_r - 1][_i])
        if _r < len(_ROWS) - 1 and _i < len(_ROWS[_r + 1]):
            _nb.add(_ROWS[_r + 1][_i])
        _ADJACENCY[_ch] = sorted(_nb)

_HOMOGLYPHS = {"o": "0", "l": "1", "e": "3", "a": "@"}
_VOWELS = "aeiou"
_KEYWORDS = ("login", "secure", "account", "verify", "support", "update", "pay", "app")
_ALT_TLDS = ("co", "net", "org", "io", "dev", "app")
_INSERT_CHARS = "aeiousx-"
_VALID = re.compile(r"^[a-z0-9@.\-]+$")


def _split_brand(brand: str) -> tuple[str, str]:
    brand = brand.strip().lower().rstrip(".")
    if "." in brand:
        label, tld = brand.rsplit(".", 1)
    else:
        label, tld = brand, "com"
    return label, tld


def generate_candidates(brand: str) -> list[str]:
    """Generate typo-squat candidates for a brand domain using 12 techniques."""
    label, tld = _split_brand(brand)
    if not label:
        return []
    base = f"{label}.{tld}"
    cands: set[str] = set()

    def add(domain: str) -> None:
        domain = domain.lower()
        if domain != base and _VALID.match(domain):
            cands.add(domain)

    n = len(label)

    # 1. omission: drop one character
    for i in range(n):
        add(f"{label[:i]}{label[i + 1 :]}.{tld}")

    # 2. insertion: add a common character at every position
    for i in range(n + 1):
        for ch in _INSERT_CHARS:
            add(f"{label[:i]}{ch}{label[i:]}.{tld}")

    # 3. substitution: swap a character for an adjacent-key neighbour
    for i, ch in enumerate(label):
        for sub in _ADJACENCY.get(ch, ()):
            add(f"{label[:i]}{sub}{label[i + 1 :]}.{tld}")

    # 4. transposition: swap each adjacent pair
    for i in range(n - 1):
        add(f"{label[:i]}{label[i + 1]}{label[i]}{label[i + 2 :]}.{tld}")

    # 5. homoglyph: o->0, l->1, e->3, a->@
    for i, ch in enumerate(label):
        if ch in _HOMOGLYPHS:
            add(f"{label[:i]}{_HOMOGLYPHS[ch]}{label[i + 1 :]}.{tld}")
    full = "".join(_HOMOGLYPHS.get(ch, ch) for ch in label)
    if full != label:
        add(f"{full}.{tld}")

    # 6. hyphenation: split the label with a hyphen
    for i in range(1, n):
        add(f"{label[:i]}-{label[i:]}.{tld}")

    # 7. tld_swap: same name, attacker-friendly TLD
    for alt in _ALT_TLDS:
        add(f"{label}.{alt}")

    # 8. pluralization: paypal -> paypals / paypales
    add(f"{label}s.{tld}")
    add(f"{label}es.{tld}")

    # 9. keyword prefix: login-paypal.com
    for kw in _KEYWORDS:
        add(f"{kw}-{label}.{tld}")

    # 10. keyword suffix: paypal-pay.com
    for kw in _KEYWORDS:
        add(f"{label}-{kw}.{tld}")

    # 11. vowel swap: paypal -> poypal
    for i, ch in enumerate(label):
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    add(f"{label[:i]}{v}{label[i + 1 :]}.{tld}")

    # 12. double-letter: paypal -> payppal
    for i, ch in enumerate(label):
        if ch in string.ascii_lowercase:
            add(f"{label[:i]}{ch}{ch}{label[i + 1 :]}.{tld}")

    return sorted(cands)


@register
class TypoWatch(Engine):
    """Detects registered lookalike domains targeting the brand."""

    name = "typo_watch"
    version = "1.0.0"
    description = (
        "Generates typo-squat variants of the brand domain with 12 squatting "
        "techniques and checks DNS + certificate-transparency signals to find "
        "registered, weaponizable lookalikes."
    )

    def scan(self, ctx: ScanContext) -> list[Finding]:
        brand = ctx.targets.get("brand_domain") or ctx.data.get("brand_domain") or ""
        if not brand:
            return []
        max_candidates = int(
            self.opt("max_candidates", ctx.option("max_candidates", 120))
        )
        min_score = float(self.opt("min_score", ctx.option("min_score", 30)))
        ct_log = set(ctx.data.get("ct_log", set()) or set())
        label = _split_brand(brand)[0]

        findings: list[Finding] = []
        for cand in generate_candidates(brand)[:max_candidates]:
            signals: dict[str, object] = {}
            a_records = ctx.dns_resolve(cand, "A")
            if a_records:
                signals["a_records"] = list(a_records)
            mx_records = ctx.dns_resolve(cand, "MX")
            if mx_records:
                signals["mx_records"] = list(mx_records)
            if cand in ct_log:
                signals["ct_log"] = True
            if label and label in cand:
                signals["brand_keyword"] = True
            if not signals:
                continue

            score = 0.0
            breakdown: dict[str, float] = {}
            if "a_records" in signals:
                score += 30
                breakdown["resolves_a"] = 30
            if "mx_records" in signals:
                score += 25
                breakdown["resolves_mx"] = 25
            if "ct_log" in signals:
                score += 20
                breakdown["in_ct_log"] = 20
            if "brand_keyword" in signals:
                score += 10
                breakdown["brand_keyword"] = 10
            if score < min_score:
                continue

            findings.append(
                self.finding(
                    title=f"Lookalike domain active: {cand}",
                    score=score,
                    entities={"domain": cand, "brand": brand},
                    evidence={
                        "candidate": cand,
                        "signals": signals,
                        "score_breakdown": breakdown,
                    },
                    recommendation=(
                        f"Investigate {cand}: check for phishing kits or cloned "
                        "login pages, file a takedown with the registrar, and "
                        "consider defensively registering the variant."
                    ),
                    tags=["typosquat", "phishing", "brand-abuse"],
                )
            )
        return findings
