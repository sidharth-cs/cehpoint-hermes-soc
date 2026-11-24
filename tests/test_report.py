"""Day 4: incident report (JSON + Markdown) and investigation history."""
import json

from tests.test_scenarios import investigate, load

from soc_agent import correlate
from soc_agent.report import append_history, build_report, read_history, refresh_actions, write_report
from soc_agent.response import decide, queue_requests

ASSESSMENT = {"alert_id": "ALR-2026-0001", "what_likely_happened": "Brute force against j.doe likely succeeded.",
              "hypotheses": [{"id": "H1", "status": "supported", "fact_ids": ["F1", "F5"], "explanation": "e"}],
              "alternative_explanations": [{"explanation": "User typo", "fact_ids": ["F2"], "why_less_likely": "new IP"}],
              "unknowns": ["whether data left the mailbox"],
              "severity_view": {"level": "critical", "agrees_with_rubric": True, "explanation": "e"},
              "recommended_actions": [{"action": "block_ip", "target": "203.0.113.45", "fact_ids": ["F1"],
                                       "justification": "Source of the brute force"}]}


def make(audit):
    alert = load("ALR-2026-0001")
    facts, calls, _ = investigate(alert)
    fd = correlate.facts_as_dicts(facts)
    reqs = queue_requests(ASSESSMENT["recommended_actions"], audit)
    report = build_report(alert, calls, correlate.build_timeline(calls), fd, correlate.attack_mapping(facts, calls),
                          correlate.assess_severity(facts), correlate.assess_confidence(facts, calls), ASSESSMENT,
                          reqs, audit.dir)
    return report, fd


def test_report_is_complete_and_evidence_linked(audit):
    report, facts = make(audit)          # build_report validates against incident_report.schema.json
    assert report["severity"]["level"] == "critical" and report["confidence"]["level"] == "high"
    assert [f["id"] for f in report["facts"]] == [f["id"] for f in facts]
    assert any(r.startswith("tests/fixtures/events.jsonl#L") for f in report["facts"] for r in f["refs"])
    assert report["response_actions"][0]["status"] == "pending_approval"
    assert len(report["tool_calls"]) == 5 and report["timeline"]


def test_markdown_shows_evidence_labels_and_pending_action(audit):
    report, _ = make(audit)
    js, md = write_report(report, audit.dir)
    text = md.read_text()
    assert json.loads(js.read_text())["report_id"] == report["report_id"]
    for needle in ("**CRITICAL**", "tests/fixtures/events.jsonl#L", "(MOCK)", "lab portal", "pending_approval",
                   "T1110.001", "F11", "Limitations"):
        assert needle in text, needle


def test_report_updates_after_approval(audit):
    report, _ = make(audit)
    write_report(report, audit.dir)
    decide(audit.dir, "A1", "Sidharth", approve=True, confirm=lambda _: "A1 203.0.113.45")
    refresh_actions(audit.dir)
    text = (audit.dir / "incident_report.md").read_text()
    assert "**executed**" in text and "Sidharth" in text


def test_history_lists_runs_with_current_action_status(audit):
    report, _ = make(audit)
    append_history(report, audit.dir.parent)
    assert read_history(audit.dir.parent)[0]["actions"] == {"pending_approval": 1}
    decide(audit.dir, "A1", "Sidharth", approve=False)
    assert read_history(audit.dir.parent)[0]["actions"] == {"rejected": 1}
