"""Day 4: the human approval gate. The agent can propose, never execute; only a named human can approve."""
import json

import pytest

from soc_agent.assess import action_targets, parse_assessment
from soc_agent.response import GateError, decide, load_requests, queue_requests
from soc_agent.tools import run_tool
from soc_agent.validation import ValidationError

PROPOSALS = [
    {"action": "block_ip", "target": "203.0.113.45", "fact_ids": ["F1", "F3"], "justification": "Brute force source"},
    {"action": "disable_account", "target": "j.doe@example.com", "fact_ids": ["F1", "F5"], "justification": "Taken over"},
]


def events(audit):
    return [json.loads(x)["event"] for x in audit.path.read_text().splitlines()]


@pytest.fixture
def queued(audit):
    queue_requests(PROPOSALS, audit)
    return audit


# --- the agent cannot reach a response action at all -------------------------------------------------------
def test_agent_toolset_has_no_response_actions(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-real-key")
    from soc_agent.hermes_runtime import build_agent
    agent = build_agent(enabled_toolsets=["soc"])
    assert set(agent.valid_tool_names) == {"search_logs", "lookup_ip", "search_cve", "get_asset_context"}
    from tools.registry import registry  # Hermes' registry: the response actions are not registered anywhere
    assert {"block_ip", "disable_account"}.isdisjoint(registry.get_all_tool_names())
    assert set(registry.get_tool_names_for_toolset("soc")) == set(agent.valid_tool_names)


def test_response_action_called_as_a_tool_is_not_permitted():
    for name in ("block_ip", "disable_account", "terminal", "write_file"):
        assert run_tool(name, {"ip": "203.0.113.45"})["error"]["code"] == "not_permitted"


# --- proposals are validated before they are even queued ----------------------------------------------------
def _assessment(actions):
    return json.dumps({"alert_id": "ALR-2026-0001", "what_likely_happened": "x",
                       "hypotheses": [{"id": "H1", "status": "supported", "fact_ids": ["F1"], "explanation": "e"}],
                       "alternative_explanations": [{"explanation": "a", "fact_ids": ["F2"], "why_less_likely": "b"}],
                       "unknowns": [], "severity_view": {"level": "critical", "agrees_with_rubric": True, "explanation": "e"},
                       "recommended_actions": actions})


def _parse(actions, alert, confirmed=frozenset({"F1", "F3", "F5"})):
    return parse_assessment(_assessment(actions), "ALR-2026-0001", {"F1", "F2", "F3", "F5", "F10", "F11"}, {"H1"},
                            "critical", confirmed_ids=set(confirmed), targets=action_targets(alert))


def test_valid_proposals_accepted(alert):
    assert len(_parse(PROPOSALS, alert)["recommended_actions"]) == 2


def test_proposal_for_target_outside_the_alert_rejected(alert):
    with pytest.raises(ValidationError, match="not an entity of this alert"):
        _parse([{**PROPOSALS[0], "target": "8.8.8.8"}], alert)


def test_proposal_backed_only_by_unconfirmed_fact_rejected(alert):
    with pytest.raises(ValidationError, match="no confirmed threat fact"):
        _parse([{**PROPOSALS[0], "fact_ids": ["F11"]}], alert)


def test_proposal_backed_only_by_context_fact_rejected(alert):
    from soc_agent.assess import ACTION_EVIDENCE
    with pytest.raises(ValidationError, match="no confirmed threat fact"):   # F10 = host criticality, not a threat
        _parse([{**PROPOSALS[1], "fact_ids": ["F10"]}], alert, confirmed=({"F1", "F10"} & ACTION_EVIDENCE))


def test_unknown_action_rejected_by_schema(alert):
    with pytest.raises(ValidationError):
        _parse([{**PROPOSALS[0], "action": "delete_mailbox"}], alert)


# --- the gate ---------------------------------------------------------------------------------------------
def test_queued_requests_are_pending_and_audited(queued, lab_calls):
    reqs = load_requests(queued.dir)
    assert [r["status"] for r in reqs] == ["pending_approval", "pending_approval"]
    assert all(r["requested_by"] == "hermes-agent" and r["target_system"].startswith("lab portal") for r in reqs)
    assert "approval_requested" in events(queued)
    assert lab_calls == []                                                 # proposing executes nothing


def test_wrong_confirmation_executes_nothing(queued, lab_calls):
    with pytest.raises(GateError, match="did not match"):
        decide(queued.dir, "A1", "Sidharth", approve=True, confirm=lambda _: "yes")
    assert load_requests(queued.dir)[0]["status"] == "pending_approval"
    assert lab_calls == []
    assert "approval_refused" in events(queued)


def test_approval_by_named_human_executes_on_lab(queued, lab_calls):
    req = decide(queued.dir, "A1", "Sidharth", approve=True, confirm=lambda _: "A1 203.0.113.45")
    assert req["status"] == "executed" and req["decided_by"] == "Sidharth"
    assert lab_calls == [{"action": "block_ip", "target": "203.0.113.45", "analyst": "Sidharth", "run_id": queued.run_id}]
    assert {"action_executed", "approval_granted"} <= set(events(queued))


def test_lab_down_means_nothing_changes(queued, monkeypatch):
    import httpx
    def down(*a, **k):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr("soc_agent.response.execute_on_lab", down)
    with pytest.raises(GateError, match="could not apply"):
        decide(queued.dir, "A1", "Sidharth", approve=True, confirm=lambda _: "A1 203.0.113.45")
    assert load_requests(queued.dir)[0]["status"] == "pending_approval"


def test_decision_cannot_be_repeated_or_reversed(queued, lab_calls):
    decide(queued.dir, "A2", "Sidharth", approve=False)
    with pytest.raises(GateError, match="already rejected"):
        decide(queued.dir, "A2", "Sidharth", approve=True, confirm=lambda _: "A2 j.doe@example.com")
    assert lab_calls == []


@pytest.mark.parametrize("who", ["", "  ", "hermes", "agent", "model"])
def test_agent_or_anonymous_cannot_approve(queued, who):
    with pytest.raises(GateError, match="human analyst"):
        decide(queued.dir, "A1", who, approve=True, confirm=lambda _: "A1 203.0.113.45")


def test_tampered_request_refused(queued):
    path = queued.dir / "approvals.json"
    doc = json.loads(path.read_text())
    doc["requests"][0]["target"] = "198.51.100.10"          # swap the target after the agent asked
    path.write_text(json.dumps(doc))
    with pytest.raises(GateError, match="modified"):
        decide(queued.dir, "A1", "Sidharth", approve=True, confirm=lambda _: "A1 198.51.100.10")


def test_cli_approval_refused_without_interactive_terminal(queued, capsys):
    from soc_agent.__main__ import main
    assert main(["approve", str(queued.dir), "A1", "--analyst", "Sidharth"]) == 5
    assert "interactive terminal" in capsys.readouterr().err
    assert load_requests(queued.dir)[0]["status"] == "pending_approval"
    assert events(queued)[-1] == "approval_refused"
