import json
import subprocess
import sys

import pytest

from soc_agent import hermes_runtime
from soc_agent.investigate import parse_evidence
from soc_agent.validation import ValidationError


def evidence(**over):
    doc = {"alert_id": "ALR-2026-0001",
           "evidence": [{"tool": "search_logs", "finding": "50 failures then 1 success", "refs": ["tests/fixtures/events.jsonl#L172"], "mock": False},
                        {"tool": "lookup_ip", "finding": "MOCK: malicious", "refs": [], "mock": True}],
           "tool_failures": [], "open_questions": []}
    doc.update(over)
    return doc


def test_valid_evidence_report_parses():
    assert parse_evidence(json.dumps(evidence()), "ALR-2026-0001")["evidence"][0]["tool"] == "search_logs"


def test_mock_source_must_be_flagged_mock():
    bad = evidence()
    bad["evidence"][1]["mock"] = False
    with pytest.raises(ValidationError, match="mock=true"):
        parse_evidence(json.dumps(bad), "ALR-2026-0001")


def test_evidence_from_unapproved_tool_is_rejected():
    bad = evidence()
    bad["evidence"][0]["tool"] = "web_search"
    with pytest.raises(ValidationError):
        parse_evidence(json.dumps(bad), "ALR-2026-0001")


def test_soc_agent_exposes_only_the_four_tools(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-real-key")
    agent = hermes_runtime.build_agent(["soc"])
    assert sorted(agent.valid_tool_names) == ["get_asset_context", "lookup_ip", "search_cve", "search_logs"]
    names = {t["function"]["name"] for t in agent.tools}
    assert not names & {"terminal", "read_file", "write_file", "web_search", "browser_navigate", "execute_code"}


def test_synthetic_data_is_reproducible(tmp_path):
    import shutil
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    before = {p: p.read_bytes() for p in (root / "tests" / "fixtures").glob("*.json*")}
    subprocess.run([sys.executable, str(root / "tests" / "fixtures" / "generate_synthetic.py")], check=True, capture_output=True)
    after = {p: p.read_bytes() for p in (root / "tests" / "fixtures").glob("*.json*")}
    assert before == after


# ---------- regression: DeepSeek sometimes writes a tool call as plain text instead of calling it
PSEUDO_CALL = ('<follow_up>\n<parameter name="search_cve">Step 7: check CVEs</parameter>\n'
               '<parameter name="query">Windows 11 privilege escalation</parameter>\n</follow_up>')


class ScriptedAgent:
    """Stands in for a Hermes AIAgent: returns scripted final responses, keeps the conversation."""

    valid_tool_names = {"search_logs", "lookup_ip", "search_cve", "get_asset_context"}

    def __init__(self, *finals):
        self.finals = list(finals)
        self.calls = []

    def run_conversation(self, user_message, system_message=None, conversation_history=None, **_):
        self.calls.append({"user": user_message, "history": conversation_history})
        text = self.finals.pop(0)
        history = list(conversation_history or []) + [{"role": "user", "content": user_message},
                                                      {"role": "assistant", "content": text}]
        return {"final_response": text, "messages": history, "api_calls": 1, "failed": False}


@pytest.fixture
def alert_and_plan():
    from tests.conftest import SAMPLE
    alert = json.loads(SAMPLE.read_text())
    plan = {"alert_id": alert["alert_id"], "summary": "s", "hypotheses": [{"id": "H1", "description": "d"}],
            "steps": [], "questions": ["q"], "safety_notes": []}
    return alert, plan


def test_pseudo_tool_call_text_is_repaired_in_same_conversation(alert_and_plan, audit):
    from soc_agent.investigate import gather_evidence
    alert, plan = alert_and_plan
    agent = ScriptedAgent(PSEUDO_CALL, json.dumps(evidence()))
    report, _ = gather_evidence(alert, plan, agent, audit)
    assert report["alert_id"] == "ALR-2026-0001"
    assert len(agent.calls) == 2
    assert agent.calls[1]["history"], "repair must continue the same conversation, not start over"
    assert "function call" in agent.calls[1]["user"]
    events = [json.loads(l)["event"] for l in audit.path.read_text().splitlines()]
    assert "evidence_rejected" in events and events[-1] == "evidence_validated"


def test_evidence_gives_up_after_repair_budget(alert_and_plan, audit):
    from soc_agent.investigate import gather_evidence
    alert, plan = alert_and_plan
    agent = ScriptedAgent(PSEUDO_CALL, PSEUDO_CALL, PSEUDO_CALL)
    with pytest.raises(ValidationError):
        gather_evidence(alert, plan, agent, audit)
    assert len(agent.calls) == 3
