"""Hermetic tests for canary_trip."""

import re

from aegis.engines.base import ScanContext
from aegis.engines.canary_trip import CanaryTrip, mint_canary


def ctx(canaries, sightings):
    return ScanContext(data={"canaries": canaries, "sightings": sightings})


CANARY = {
    "id": "canary-abc123",
    "kind": "aws",
    "token": "AKIAZZZZTOPSECRET0001",
    "location": "/opt/app/config/backup.env",
    "created": "2026-01-01T00:00:00Z",
}


def test_tripwire_fires_critical():
    sightings = [
        "2026-10-03 deploy ok",
        "grep found AKIAZZZZTOPSECRET0001 in leaked repo dump",
    ]
    f = CanaryTrip().scan(ctx([CANARY], sightings))
    assert len(f) == 1
    assert f[0].score == 100
    assert f[0].severity == "critical"
    assert "Honeytoken tripped" in f[0].title
    assert f[0].evidence["canary_id"] == "canary-abc123"
    assert f[0].evidence["kind"] == "aws"
    assert f[0].evidence["location"] == "/opt/app/config/backup.env"
    assert f[0].evidence["first_seen"]


def test_no_trip_no_findings():
    sightings = ["all quiet", "deploy ok", "AKIA-something-else-here"]
    assert CanaryTrip().scan(ctx([CANARY], sightings)) == []


def test_partial_token_does_not_trip():
    # substring of the token is not the token
    sightings = ["saw AKIAZZZZTOPSECRET in a log"]
    assert CanaryTrip().scan(ctx([CANARY], sightings)) == []


def test_one_finding_per_canary():
    sightings = [
        f"hit1 {CANARY['token']}",
        f"hit2 {CANARY['token']}",
        f"hit3 {CANARY['token']}",
    ]
    f = CanaryTrip().scan(ctx([CANARY], sightings))
    assert len(f) == 1


def test_multiple_canaries_each_trip():
    c2 = dict(CANARY, id="canary-def456", token="https://canary-aa11.example.net/ping")
    sightings = [f"saw {CANARY['token']} and {c2['token']}"]
    f = CanaryTrip().scan(ctx([CANARY, c2], sightings))
    assert len(f) == 2


def test_evidence_never_echoes_token():
    f = CanaryTrip().scan(ctx([CANARY], [f"leak: {CANARY['token']}"]))
    assert CANARY["token"] not in str(f[0].evidence)


def test_mint_canary_aws_format():
    c = mint_canary("aws")
    assert c["kind"] == "aws"
    assert re.fullmatch(r"AKIA[A-Z0-9]{16}", c["token"])
    assert c["id"].startswith("canary-")


def test_mint_canary_url_format():
    c = mint_canary("url")
    assert c["kind"] == "url"
    assert re.fullmatch(r"https://canary-[0-9a-f]{8}\.example\.net/ping", c["token"])


def test_mint_canary_cred_format():
    c = mint_canary("cred")
    assert c["kind"] == "cred"
    assert re.fullmatch(r"canary_svc_[0-9a-f]{12}", c["token"])


def test_mint_canary_tokens_unique():
    tokens = {mint_canary("aws")["token"] for _ in range(50)}
    assert len(tokens) == 50


def test_empty_inputs():
    assert CanaryTrip().scan(ScanContext(data={})) == []
    assert CanaryTrip().scan(ctx([], [])) == []
