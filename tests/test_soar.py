"""Hermetic tests for the aegis.soar actions and playbook engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.soar import ACTIONS, AUDIT_LOG, PlaybookEngine, get_audit_log
from aegis.soar import actions

LIBRARY_DIR = Path(__file__).resolve().parent.parent / "aegis" / "soar" / "library"


@pytest.fixture(autouse=True)
def clean_audit_log():
    AUDIT_LOG.clear()
    yield
    AUDIT_LOG.clear()


@pytest.fixture()
def engine():
    return PlaybookEngine(LIBRARY_DIR)


# -- actions --------------------------------------------------------------
def test_block_ip_rejects_invalid_ip():
    with pytest.raises(ValueError):
        actions.block_ip("not-an-ip")
    with pytest.raises(ValueError):
        actions.block_ip("999.1.1.1")


def test_block_ip_dry_run_result():
    out = actions.block_ip("203.0.113.9", duration="24h", dry_run=True)
    assert out["action"] == "block_ip"
    assert out["params"] == {"ip": "203.0.113.9", "duration": "24h"}
    assert out["result"].startswith("would execute:")
    assert out["dry_run"] is True


def test_action_live_result_differs_from_dry_run():
    dry = actions.isolate_host("web-01", dry_run=True)
    live = actions.isolate_host("web-01", dry_run=False)
    assert dry["result"].startswith("would execute:")
    assert live["result"].startswith("executed:")
    assert live["dry_run"] is False


@pytest.mark.parametrize(
    "call",
    [
        lambda: actions.isolate_host(""),
        lambda: actions.revoke_token("   "),
        lambda: actions.disable_user(None),
        lambda: actions.notify("security-ops", ""),
        lambda: actions.create_ticket("jira", ""),
        lambda: actions.open_case("", severity="high"),
        lambda: actions.open_case("x", severity="nonsense"),
    ],
)
def test_actions_validate_params(call):
    with pytest.raises(ValueError):
        call()


def test_audit_log_records_every_call():
    actions.block_ip("203.0.113.9", dry_run=True)
    actions.notify("security-ops", "hello", dry_run=True)
    log = get_audit_log()
    assert len(log) == 2
    assert log[0]["action"] == "block_ip"
    assert log[1]["action"] == "notify"
    assert all("ts" in entry for entry in log)
    # snapshot, not a live reference
    assert get_audit_log() is not log


def test_actions_registry_complete():
    assert set(ACTIONS) == {
        "block_ip",
        "isolate_host",
        "revoke_token",
        "disable_user",
        "open_case",
        "notify",
        "create_ticket",
    }


# -- library --------------------------------------------------------------
def test_library_loads_all_six_with_valid_schema(engine):
    assert len(engine.library) == 6
    names = sorted(pb["name"] for pb in engine.library)
    assert names == [
        "brute-force-response",
        "cloud-misconfig-remediate",
        "cve-patch-ticket",
        "phishing-containment",
        "secret-leak-rotation",
        "typosquat-takedown",
    ]
    for pb in engine.library:
        assert pb["description"].strip()
        assert isinstance(pb["trigger"]["engines"], list)
        for step in pb["steps"]:
            assert step["action"] in ACTIONS


def test_load_library_rejects_bad_schema(tmp_path):
    (tmp_path / "bad.yml").write_text(
        "name: broken\nsteps: []\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="invalid playbook"):
        PlaybookEngine(tmp_path)


# -- matching -------------------------------------------------------------
def test_match_returns_playbook(engine):
    pb = engine.match(
        {
            "engine": "auth_watch",
            "severity": "high",
            "entities": {"ip": "203.0.113.9"},
        }
    )
    assert pb is not None
    assert pb["name"] == "brute-force-response"


def test_match_rejects_wrong_engine_and_low_severity(engine):
    assert (
        engine.match(
            {"engine": "dns_sentinel", "severity": "critical", "entities": {}}
        )
        is None
    )
    # medium is below the brute-force playbook's high minimum
    assert (
        engine.match(
            {
                "engine": "auth_watch",
                "severity": "medium",
                "entities": {"ip": "203.0.113.9"},
            }
        )
        is None
    )


# -- execution ------------------------------------------------------------
def test_run_executes_steps_with_templating(engine):
    pb = engine.match(
        {"engine": "auth_watch", "severity": "high", "entities": {}}
    )
    trigger = {
        "engine": "auth_watch",
        "severity": "high",
        "entities": {"ip": "203.0.113.9", "user": "admin"},
    }
    run = engine.run(pb, trigger, dry_run=True)
    assert run.status == "completed"
    assert run.dry_run is True
    assert len(run.steps) == 3
    block = run.steps[0]
    assert block["action"] == "block_ip"
    assert block["params"] == {"ip": "203.0.113.9", "duration": "24h"}
    assert block["result"].startswith("would execute:")
    assert "admin" in run.steps[1]["params"]["message"]
    assert run.steps[2]["params"]["title"] == "Brute-force campaign against admin"
    # the run itself was audited
    assert len(get_audit_log()) == 3


def test_run_records_approval_required(engine):
    pb = engine.match(
        {"engine": "phish_kit", "severity": "high", "entities": {}}
    )
    trigger = {
        "engine": "phish_kit",
        "severity": "high",
        "entities": {"ip": "203.0.113.9", "host": "web-01"},
    }
    run = engine.run(pb, trigger, dry_run=True)
    isolate = next(s for s in run.steps if s["action"] == "isolate_host")
    assert isolate["approval_required"] is True
    assert isolate["approved"] is False
    assert isolate["params"] == {"host": "web-01"}
    plain = run.steps[0]
    assert plain["approval_required"] is False
    assert plain["approved"] is True
    assert run.status == "completed"


def test_run_unknown_action_gives_partial_and_continues(engine):
    pb = {
        "name": "broken-demo",
        "steps": [
            {"action": "no_such_action", "params": {}},
            {"action": "notify", "params": {"channel": "soc", "message": "hi"}},
        ],
    }
    run = engine.run(pb, {"engine": "auth_watch", "severity": "high", "entities": {}}, dry_run=True)
    assert run.status == "partial"
    assert run.steps[0]["result"].startswith("error:")
    assert run.steps[1]["result"].startswith("would execute:")


def test_run_action_validation_error_marks_step_error(engine):
    pb = {
        "name": "bad-ip-demo",
        "steps": [
            {"action": "block_ip", "params": {"ip": "{ip}"}},
            {"action": "notify", "params": {"channel": "soc", "message": "done"}},
        ],
    }
    trigger = {
        "engine": "auth_watch",
        "severity": "high",
        "entities": {"ip": "not-an-ip"},
    }
    run = engine.run(pb, trigger, dry_run=True)
    assert run.status == "partial"
    assert "valid IPv4" in run.steps[0]["result"]
    assert run.steps[1]["result"].startswith("would execute:")
