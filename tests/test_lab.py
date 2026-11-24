"""The lab portal (the system we own), the detector, and real enforcement of approved actions. No network."""
import json

import pytest
from fastapi.testclient import TestClient

import lab.app as portal
from soc_agent import detect
from soc_agent.tools import data

ATTACKER = {"X-Forwarded-For": "203.0.113.45", "User-Agent": "python-httpx/0.28"}


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setattr(portal, "STATE", tmp_path)
    with TestClient(portal.app) as c:
        yield c, tmp_path


def events(state):
    return [json.loads(x) for x in (state / "events.jsonl").read_text().splitlines()]


def brute_force(c, n_fail=12):
    for _ in range(n_fail):
        assert c.post("/login", headers=ATTACKER, json={"username": "j.doe@lab.example", "password": "nope"}).status_code == 401
    r = c.post("/login", headers=ATTACKER, json={"username": "j.doe@lab.example", "password": "Welcome@2026"})
    assert r.status_code == 200
    return r.json()["token"]


def test_every_request_is_logged_with_ip_and_user_agent(lab):
    c, state = lab
    token = brute_force(c, 2)
    c.post("/mail/rules", headers={**ATTACKER, "Authorization": f"Bearer {token}"},
           json={"name": "x", "forward_to": "out@exfil-lab.example.net"})
    ev = events(state)
    assert [e["event_type"] for e in ev] == ["auth_failure", "auth_failure", "auth_success", "mailbox_rule_created"]
    assert all(e["src_ip"] == "203.0.113.45" and e["host"] == "LAB-PORTAL-01" for e in ev)
    assert ev[0]["details"]["user_agent"] == "python-httpx/0.28" and ev[2]["details"]["mfa"] == "not_enrolled"


def test_mfa_account_needs_the_one_time_code(lab):
    c, _ = lab
    body = {"username": "m.lee@lab.example", "password": "Hx2!river-Orbit-55"}
    assert c.post("/login", json=body).status_code == 401
    assert c.post("/login", json={**body, "otp": "736204"}).status_code == 200


def test_detector_raises_alert_from_live_events(lab):
    c, state = lab
    brute_force(c)
    hits = detect.detect(events(state))
    assert len(hits) == 1 and len(hits[0]["failures"]) == 12
    alert = detect.to_alert("ALR-2026-1001", hits[0])          # validated against alert.schema.json
    assert alert["entities"] == {"account": "j.doe@lab.example", "host": "LAB-PORTAL-01",
                                 "source_ips": ["203.0.113.45"], "domains": []}
    assert alert["data_provenance"] == "lab"
    from soc_agent import correlate                           # millisecond events inside a to-the-second window
    calls = [{"tool": "search_logs", "ok": True, "arguments": {"account": "j.doe@lab.example", "start": alert["observations"]["window_start"],
              "end": alert["observations"]["window_end"]}, "result": {"events": [{**e, "ref": f"L{i}"} for i, e in enumerate(events(state))]}}]
    f1 = correlate.build_facts(alert, calls)[0]
    assert f1.status == "confirmed" and f1.data["failures"] == 12


def test_detector_ignores_a_few_typos(lab):
    c, state = lab
    brute_force(c, 3)
    assert detect.detect(events(state)) == []


def test_detector_finds_the_fixture_scenario():
    hits = detect.detect(data.load_events()[0])
    assert any(h["account"] == "j.doe@example.com" and len(h["failures"]) >= detect.THRESHOLD for h in hits)


def test_admin_api_needs_the_token(lab):
    c, _ = lab
    body = {"target": "203.0.113.45", "action_id": "A1", "approved_by": "x", "run_id": "r"}
    assert c.post("/admin/block_ip", json=body).status_code == 401
    assert c.post("/admin/block_ip", headers={"X-Admin-Token": "guess"}, json=body).status_code == 401


def test_approved_block_stops_the_attacker(lab):
    c, state = lab
    brute_force(c)
    token = (state / "admin_token").read_text()
    r = c.post("/admin/block_ip", headers={"X-Admin-Token": token},
               json={"target": "203.0.113.45", "action_id": "A1", "approved_by": "Sidharth", "run_id": "r1"})
    assert r.status_code == 200
    r = c.post("/login", headers=ATTACKER, json={"username": "j.doe@lab.example", "password": "Welcome@2026"})
    assert r.status_code == 403 and "blocked" in r.json()["detail"]
    office = c.post("/login", headers={"X-Forwarded-For": "198.51.100.10"},
                    json={"username": "j.doe@lab.example", "password": "Welcome@2026"})
    assert office.status_code == 200                             # only the attacker's IP is blocked
    assert [e["event_type"] for e in events(state)][-3:] == ["response_action", "blocked_request", "auth_success"]
    from soc_agent import correlate                           # portal events without an account must not break output
    from soc_agent.report import render_markdown
    rows = correlate.collapse_timeline([{**e, "ref": f"L{i}"} for i, e in enumerate(events(state))])
    assert any(r["account"] is None for r in rows)
    assert "blocked_request | - |" in render_markdown({"report_id": "IR-x", "data_provenance": "lab", "alert": {}, "generated_at": "t",
        "orchestrator": "o", "severity": {"level": "low", "reasons": []}, "confidence": {"level": "low", "reasons": []},
        "summary": "s", "model_severity_view": {"level": "low", "agrees_with_rubric": True, "explanation": ""},
        "hypotheses": [], "alternative_explanations": [], "unknowns": [], "facts": [], "attack_mapping": [], "timeline": rows,
        "response_actions": [], "tool_calls": [], "artifacts": {}, "limitations": [], "run_id": "r", "alert_id": "ALR-2026-1001"})


def test_disabled_account_cannot_log_in_and_session_ends(lab):
    c, state = lab
    session = brute_force(c)
    c.post("/admin/disable_account", headers={"X-Admin-Token": (state / "admin_token").read_text()},
           json={"target": "j.doe@lab.example", "action_id": "A2", "approved_by": "Sidharth", "run_id": "r1"})
    assert c.get("/files/payables", headers={"Authorization": f"Bearer {session}"}).status_code == 401
    r = c.post("/login", headers={"X-Forwarded-For": "198.51.100.10"},
               json={"username": "j.doe@lab.example", "password": "Welcome@2026"})
    assert r.status_code == 403


def test_status_page_shows_events_and_blocks(lab):
    c, state = lab
    brute_force(c, 2)
    c.post("/admin/block_ip", headers={"X-Admin-Token": (state / "admin_token").read_text()},
           json={"target": "203.0.113.45", "action_id": "A1", "approved_by": "Sidharth", "run_id": "r1"})
    page = c.get("/").text
    assert "BLOCKED IP <b>203.0.113.45</b>" in page and "auth_failure" in page and "Sidharth" in page
