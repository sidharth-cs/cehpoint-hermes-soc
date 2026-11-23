import json

import pytest

from soc_agent import planner
from soc_agent.validation import ValidationError
from tests.conftest import clone


def fake_llm(*outputs):
    """Returns canned model outputs in order, like a scripted model."""
    queue = list(outputs)
    calls = []

    def call(system, user):
        calls.append((system, user))
        return queue.pop(0), {"provider": "fake", "model": "fake", "api_calls": 1, "tool_calls": 0}

    call.calls = calls
    return call


def test_valid_plan_is_accepted(alert, good_plan, audit):
    plan = planner.make_plan(alert, fake_llm(json.dumps(good_plan)), audit)
    assert [s["tool"] for s in plan["steps"]] == ["search_logs", "lookup_ip", "none"]


def test_plan_in_markdown_fence_is_accepted(alert, good_plan, audit):
    text = "```json\n" + json.dumps(good_plan) + "\n```"
    assert planner.make_plan(alert, fake_llm(text), audit)["alert_id"] == "ALR-2026-0001"


def test_unapproved_tool_is_rejected(good_plan):
    bad = clone(good_plan)
    bad["steps"][0]["tool"] = "run_shell"
    with pytest.raises(ValidationError, match="run_shell"):
        planner.parse_plan(json.dumps(bad), "ALR-2026-0001")


def test_wrong_alert_id_is_rejected(good_plan):
    with pytest.raises(ValidationError, match="does not match"):
        planner.parse_plan(json.dumps(good_plan), "ALR-2026-9999")


def test_unknown_hypothesis_reference_is_rejected(good_plan):
    bad = clone(good_plan)
    bad["steps"][1]["tests_hypotheses"] = ["H7"]
    with pytest.raises(ValidationError, match="H7"):
        planner.parse_plan(json.dumps(bad), "ALR-2026-0001")


def test_out_of_order_steps_are_rejected(good_plan):
    bad = clone(good_plan)
    bad["steps"][1]["step"] = 5
    with pytest.raises(ValidationError, match="numbered"):
        planner.parse_plan(json.dumps(bad), "ALR-2026-0001")


def test_prose_output_triggers_one_repair_then_succeeds(alert, good_plan, audit):
    llm = fake_llm("Sure! Here is my plan: step one, look at logs.", json.dumps(good_plan))
    plan = planner.make_plan(alert, llm, audit)
    assert plan["alert_id"] == "ALR-2026-0001"
    assert "rejected" in llm.calls[1][1]  # second prompt carries the rejection reasons
    events = [json.loads(l)["event"] for l in audit.path.read_text().splitlines()]
    assert events == ["plan_requested", "llm_response", "plan_rejected", "llm_response", "plan_validated"]


def test_gives_up_after_repair_budget(alert, audit):
    with pytest.raises(ValidationError):
        planner.make_plan(alert, fake_llm("nope", "still nope"), audit)


def test_audit_records_prompt_and_raw_output(alert, good_plan, audit):
    planner.make_plan(alert, fake_llm(json.dumps(good_plan)), audit)
    lines = [json.loads(l) for l in audit.path.read_text().splitlines()]
    assert "ALR-2026-0001" in lines[0]["user_prompt"]
    assert lines[1]["output"] == json.dumps(good_plan)
    assert all("ts" in l and "run_id" in l for l in lines)
