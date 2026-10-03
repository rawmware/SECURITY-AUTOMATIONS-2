"""Test fixtures: app/client plus deterministic sim-data builders.

The real 12-engine fleet is used (registered by ``load_engines``). Sim data
is crafted so exactly one engine fires deterministically:

- ``typo_watch`` fires when ``targets["brand_domain"]`` is set and
  ``sim_data["ct_log"]`` contains generated lookalike candidates that still
  embed the brand label (ct_log +20, brand_keyword +10 = score 30 → "low").
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis import __version__
from aegis.api import create_app
from aegis.config import AegisConfig
from aegis.engines.typo_watch import generate_candidates

#: The 12 engine names the fleet registers.
EXPECTED_ENGINES = [
    "anomaly_mind",
    "auth_watch",
    "canary_trip",
    "cloud_posture",
    "cve_watch",
    "dns_sentinel",
    "phish_kit",
    "port_watch",
    "secret_sentry",
    "tls_watch",
    "typo_watch",
    "url_intel",
]

BRAND = "example.test"


def typo_sim(n: int = 2) -> tuple[dict, dict]:
    """(targets, sim_data) that make typo_watch emit exactly ``n`` findings."""
    cands = sorted(
        c
        for c in generate_candidates(BRAND)
        if "example" in c and c != BRAND
    )[:n]
    assert len(cands) == n, "need deterministic typo candidates"
    return {"brand_domain": BRAND}, {"ct_log": list(cands)}


@pytest.fixture()
def config() -> AegisConfig:
    return AegisConfig(brand_domain="unused.test")


@pytest.fixture()
def app(config: AegisConfig):
    return create_app(config)


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def version() -> str:
    return __version__
