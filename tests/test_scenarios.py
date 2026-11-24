"""Day 3 scenario test cases: the deterministic correlation, severity and confidence on real tool output.

These call the real tools (no model), so each scenario is exactly what the agent would see.
"""
import json
from pathlib import Path

import pytest

from soc_agent import correlate
from soc_agent.tools import BY_NAME, run_tool, start_trace, stop_trace

ALERTS = Path(__file__).resolve().parent.parent / "data" / "alerts"
R = "Gathering evidence for this investigation step."


def load(alert_id):
    return json.loads((ALERTS / f"{alert_id}.json").read_text())


def investigate(alert, *, lookback=True, post_login=True, ip_scope=True, assets=True, intel=True, cve=True):
    """Runs the tool calls a thorough analyst would make; switches simulate a less complete investigation."""
    a = alert["entities"]["account"]
    ip = alert["entities"]["source_ips"][0]
    ws, we = alert["observations"]["window_start"], alert["observations"]["window_end"]
    t = start_trace()
    try:
        start = "2026-10-24T00:00:00Z" if lookback else ws
        end = "2026-11-23T06:00:00Z" if post_login else we
        if alert["alert_id"] == "ALR-2026-0003":
            start = "2026-11-01T00:00:00Z" if lookback else ws
            end = "2026-11-11T06:00:00Z" if post_login else we
        run_tool("search_logs", {"reason": R, "account": a, "start": start, "end": end, "limit": 200})
        if ip_scope:
            run_tool("search_logs", {"reason": R, "src_ip": ip, "start": ws, "end": we, "limit": 200})
        if assets:
            run_tool("get_asset_context", {"reason": R, "account": a, "host": alert["entities"]["host"]})
        if intel:
            run_tool("lookup_ip", {"reason": R, "ip": ip})
        if cve:
            run_tool("search_cve", {"reason": R, "query": "brute force password spray valid accounts"})
    finally:
        stop_trace()
    facts = correlate.build_facts(alert, t.calls)
    return facts, t.calls, {f.id: f for f in facts}


# 1. Suspicious: the mandatory scenario with complete evidence
def test_scenario_suspicious_account_compromise():
    facts, calls, by = investigate(load("ALR-2026-0001"))
    assert by["F1"].status == "confirmed" and by["F1"].data["failures"] == 50
    assert by["F2"].status == "confirmed"           # IP new for the account
    assert by["F3"].status == "confirmed"           # same IP sprayed 2 other accounts
    assert by["F5"].status == "confirmed" and by["F6"].status == "confirmed"
    assert correlate.assess_severity(facts)["level"] == "critical"
    assert correlate.assess_confidence(facts, calls)["level"] == "high"
    assert {m["technique"] for m in correlate.attack_mapping(facts, calls)} == {"T1110.001", "T1110.003", "T1078", "T1114.003", "T1039"}
    for f in facts:                                  # every confirmed log-based fact cites evidence
        if f.status == "confirmed" and f.tools == ["search_logs"] and f.id != "F2":
            assert f.refs and all(r.startswith("data/logs/events.jsonl#L") for r in f.refs)


# 2. Incomplete: no look-back and nothing searched after the login
def test_scenario_incomplete_evidence_is_unknown_not_assumed():
    facts, calls, by = investigate(load("ALR-2026-0001"), lookback=False, post_login=False)
    assert by["F1"].status == "confirmed"
    assert by["F2"].status == "unknown" and "not searched" in by["F2"].statement
    assert by["F4"].status == by["F5"].status == by["F6"].status == "unknown"
    sev = correlate.assess_severity(facts)
    assert sev["level"] == "high"                    # not critical: the escalating facts are unknown, not assumed
    conf = correlate.assess_confidence(facts, calls)
    assert conf["level"] in ("medium", "low") and "gaps" in conf["reasons"][0]
    assert "T1114.003" not in {m["technique"] for m in correlate.attack_mapping(facts, calls)}


# 3. Tool failure: the intel service times out
def test_scenario_tool_failure_lowers_confidence_not_severity(monkeypatch):
    monkeypatch.setenv("SOC_FAULTS", "lookup_ip=timeout")
    monkeypatch.setattr(BY_NAME["lookup_ip"], "timeout_s", 0.2)
    facts, calls, by = investigate(load("ALR-2026-0001"))
    assert by["F11"].status == "unknown" and "timeout" in by["F11"].statement
    assert correlate.assess_severity(facts)["level"] == "critical"   # severity rests on log evidence, not intel
    conf = correlate.assess_confidence(facts, calls)
    assert conf["level"] == "medium" and any("lookup_ip=timeout" in r for r in conf["reasons"])


# 4. Benign: a privileged user mistypes once and logs in from the office
def test_scenario_benign_typo():
    facts, calls, by = investigate(load("ALR-2026-0003"))
    assert by["F1"].status == "not_observed" and by["F1"].data["failures"] == 1
    assert by["F9"].status == "not_observed"        # usual IP, usual hours
    assert by["F11"].status == "not_observed"       # intel says benign corporate egress
    sev = correlate.assess_severity(facts)
    assert sev["level"] == "low" and any("usual IP" in r for r in sev["reasons"])
    assert correlate.attack_mapping(facts, calls) == []


# 5. Attempted, not successful: the sprayed account that held
def test_scenario_attempt_without_success():
    facts, calls, by = investigate(load("ALR-2026-0002"))
    assert by["F1"].status == "not_observed" and by["F1"].data["failures"] == 12
    assert by["F3"].status == "confirmed" and "j.doe@example.com" in by["F3"].statement
    sev = correlate.assess_severity(facts)
    assert sev["level"] == "medium" and any("F3" in r for r in sev["reasons"])
    assert {m["technique"] for m in correlate.attack_mapping(facts, calls)} == {"T1110.001", "T1110.003"}


# 6. Conflicting: brute-force pattern but the login came from the user's usual IP at usual hours
def test_scenario_conflicting_evidence_lowers_confidence():
    alert = load("ALR-2026-0001")
    facts, calls, by = investigate(alert)
    for c in calls:   # pretend the asset inventory lists the attacker IP as usual and widens hours
        if c["tool"] == "get_asset_context":
            c["result"]["account"]["usual_ips"].append("203.0.113.45")
            c["result"]["account"]["usual_hours_utc"] = "00:00-23:59"
    facts = correlate.build_facts(alert, calls)
    by = {f.id: f for f in facts}
    assert by["F1"].status == "confirmed" and by["F9"].status == "not_observed"
    conf = correlate.assess_confidence(facts, calls)
    assert any("conflict" in r for r in conf["reasons"]) and conf["level"] != "high"


# 7. Nothing searched at all: every log-based fact is unknown, severity is not downgraded below the hint level
def test_scenario_no_evidence_gathered():
    alert = load("ALR-2026-0001")
    t = start_trace()
    stop_trace()
    facts = correlate.build_facts(alert, t.calls)
    by = {f.id: f for f in facts}
    assert all(by[i].status == "unknown" for i in ("F1", "F2", "F3", "F4", "F8", "F11"))
    assert correlate.assess_severity(facts)["level"] == "medium"
    assert correlate.assess_confidence(facts, t.calls)["level"] == "low"


def test_timeline_is_sorted_deduplicated_and_cited():
    _, calls, _ = investigate(load("ALR-2026-0001"))
    tl = correlate.build_timeline(calls)
    assert [e["ts"] for e in tl] == sorted(e["ts"] for e in tl)
    assert len({e["event_id"] for e in tl}) == len(tl)
    rows = correlate.collapse_timeline([e for e in tl if "2026-11-23T02:58" <= e["ts"] <= "2026-11-23T03:30"])
    burst = next(r for r in rows if r["count"] == 50)
    assert burst["event_type"] == "auth_failure" and burst["src_ip"] == "203.0.113.45"
