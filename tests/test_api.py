"""Tests for the Aegis HTTP API (routes + websocket stream)."""

from __future__ import annotations

from aegis import __version__
from aegis.models import Finding
from tests.conftest import EXPECTED_ENGINES, typo_sim


def _scan_payload():
    targets, sim_data = typo_sim()
    return {"targets": targets, "sim_data": sim_data}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
    assert body["engines"] == 12


def test_engines_lists_twelve(client):
    r = client.get("/engines")
    assert r.status_code == 200
    engines = r.json()
    assert len(engines) == 12
    assert {e["name"] for e in engines} == set(EXPECTED_ENGINES)
    for e in engines:
        assert e["version"] and e["description"] and isinstance(e["enabled"], bool)


def test_post_scan_returns_findings(client):
    r = client.post("/scan", json=_scan_payload())
    assert r.status_code == 200
    body = r.json()
    assert len(body["findings"]) == 2
    assert "typo_watch" in body["engines_run"]
    assert body["errors"] == []
    first = body["findings"][0]
    assert first["engine"] == "typo_watch"
    assert first["severity"] in ("informational", "low", "medium", "high", "critical")


def test_findings_filters(client):
    client.post("/scan", json=_scan_payload())

    r = client.get("/findings", params={"severity": "low"})
    assert r.status_code == 200
    assert len(r.json()) == 2
    assert all(f["severity"] == "low" for f in r.json())

    r = client.get("/findings", params={"severity": "critical"})
    assert r.status_code == 200
    assert r.json() == []

    r = client.get("/findings", params={"engine": "typo_watch"})
    assert r.status_code == 200
    assert len(r.json()) == 2
    assert all(f["engine"] == "typo_watch" for f in r.json())

    r = client.get("/findings", params={"engine": "dns_sentinel"})
    assert r.status_code == 200
    assert r.json() == []


def test_cases_endpoints(client):
    client.post("/scan", json=_scan_payload())
    r = client.get("/cases")
    assert r.status_code == 200
    assert isinstance(r.json(), list)

    r = client.get("/cases/definitely-not-a-case")
    assert r.status_code == 404


def test_stream_receives_finding(client, app):
    with client.websocket_connect("/stream") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"

        finding = Finding(
            engine="typo_watch",
            title="stream probe",
            severity="high",
            score=88.0,
        )
        app.state.bus.publish("findings", finding)

        msg = ws.receive_json()
        assert msg["type"] == "finding"
        assert msg["finding"]["engine"] == "typo_watch"
        assert msg["finding"]["title"] == "stream probe"


def test_soar_run_dry_run(client):
    r = client.post(
        "/soar/run",
        json={
            "playbook": "typosquat-takedown",
            "trigger": {
                "engine": "typo_watch",
                "severity": "high",
                "entities": {"domain": "evil-example.test"},
            },
            "dry_run": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["playbook"] == "typosquat-takedown"
    assert body["dry_run"] is True
    assert body["status"] in ("simulated", "completed", "partial")
    assert isinstance(body["steps"], list) and body["steps"]
    assert all("action" in s for s in body["steps"])


def test_soar_run_unknown_playbook_404(client):
    r = client.post(
        "/soar/run",
        json={"playbook": "nope-not-real", "trigger": {}, "dry_run": True},
    )
    assert r.status_code == 404


def test_alerts_empty_initially(client):
    r = client.get("/alerts")
    assert r.status_code == 200
    assert r.json() == []
