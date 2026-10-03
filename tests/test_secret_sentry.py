"""Hermetic tests for secret_sentry."""

import pytest

from aegis.engines.base import ScanContext
from aegis.engines.secret_sentry import SecretSentry

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_PAT = "ghp_" + "aB3dEf7hIj9kLmNoPqRsT1"
AWS_SECRET_VALUE = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7b...\n-----END RSA PRIVATE KEY-----"
HIGH_ENTROPY_VALUE = "sk_live_9f8Kq2mZxVbN4wRtY7uLp"


def ctx(texts, **options):
    return ScanContext(data={"texts": texts}, options=options)


def test_detects_aws_access_key():
    f = SecretSentry().scan(ctx({"repo.py": f"key = '{AWS_KEY}'"}))
    assert len(f) == 1
    assert f[0].score == 90
    assert f[0].severity == "critical"
    assert f[0].evidence["pattern"] == "aws_access_key"


def test_detects_github_pat():
    f = SecretSentry().scan(ctx({"ci.yml": f"token: {GITHUB_PAT}"}))
    assert len(f) == 1
    assert f[0].score == 85
    assert f[0].evidence["pattern"] == "github_pat"


def test_detects_private_key():
    f = SecretSentry().scan(ctx({"id_rsa": PRIVATE_KEY}))
    assert len(f) == 1
    assert f[0].score == 95
    assert f[0].severity == "critical"


def test_detects_aws_secret_near_label():
    text = f"config aws_secret = {AWS_SECRET_VALUE} # prod"
    f = SecretSentry().scan(ctx({"cfg": text}))
    assert len(f) == 1
    assert f[0].score == 90
    assert f[0].evidence["pattern"] == "aws_secret"


def test_bare_40char_token_without_label_is_ignored():
    f = SecretSentry().scan(ctx({"blob": f"random blob {AWS_SECRET_VALUE} here"}))
    assert f == []


def test_generic_high_entropy_key_detected():
    f = SecretSentry().scan(ctx({"app.py": f"api_key = '{HIGH_ENTROPY_VALUE}'"}))
    assert len(f) == 1
    assert f[0].score == 70
    assert f[0].severity == "high"


def test_generic_low_entropy_password_rejected():
    # 20 chars — long enough to reach the entropy gate, but English-like,
    # so shannon_entropy < 4.2 must reject it.
    f = SecretSentry().scan(ctx({"app.py": "password=changemechangeme123"}))
    assert f == []


def test_clean_text_no_findings():
    f = SecretSentry().scan(
        ctx({"notes.md": "The quarterly review is on Friday. Bring coffee."})
    )
    assert f == []


def test_dedupe_identical_secrets_by_sha():
    texts = {"a.py": f"k={AWS_KEY}", "b.py": f"again: {AWS_KEY}"}
    f = SecretSentry().scan(ctx(texts))
    assert len(f) == 1


def test_allowlist_ignores_substrings():
    f = SecretSentry().scan(ctx({"t": f"key={AWS_KEY}"}, allowlist=["IOSFODNN7"]))
    assert f == []


def test_evidence_never_contains_raw_secret():
    text = f"api_key='{HIGH_ENTROPY_VALUE}' token: {GITHUB_PAT} k={AWS_KEY}"
    findings = SecretSentry().scan(ctx({"t": text}))
    assert findings, "expected findings to redact"
    for f in findings:
        blob = str(f.evidence)
        assert HIGH_ENTROPY_VALUE not in blob
        assert GITHUB_PAT not in blob
        assert AWS_KEY not in blob
        assert f.evidence["preview"].endswith("…")
