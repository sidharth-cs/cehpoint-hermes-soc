import json

import pytest

from soc_agent.assess import make_assessment, parse_assessment
from soc_agent.validation import ValidationError

FACTS = {"F1", "F2", "F5"}
HYPS = {"H1", "H2"}


def doc(**over):
    d = {"alert_id": "ALR-2026-0001", "what_likely_happened": "Brute force succeeded and the session set up mail forwarding.",
         "hypotheses": [{"id": "H1", "status": "supported", "fact_ids": ["F1", "F5"], "explanation": "e"},
                        {"id": "H2", "status": "refuted", "fact_ids": ["F2"], "explanation": "e"}],
         "alternative_explanations": [{"explanation": "User forgot password", "fact_ids": ["F2"], "why_less_likely": "new IP"}],
         "unknowns": ["whether mail was actually forwarded"],
         "severity_view": {"level": "critical", "agrees_with_rubric": True, "explanation": "e"}}
    d.update(over)
    return d


def test_valid_assessment():
    assert parse_assessment(json.dumps(doc()), "ALR-2026-0001", FACTS, HYPS, "critical")["hypotheses"][0]["status"] == "supported"


def test_citing_a_fact_that_does_not_exist_is_rejected():
    bad = doc()
    bad["hypotheses"][0]["fact_ids"] = ["F1", "F99"]
    with pytest.raises(ValidationError, match="F99"):
        parse_assessment(json.dumps(bad), "ALR-2026-0001", FACTS, HYPS, "critical")


def test_supported_without_evidence_is_rejected():
    bad = doc()
    bad["hypotheses"][0]["fact_ids"] = []
    with pytest.raises(ValidationError, match="cites no facts"):
        parse_assessment(json.dumps(bad), "ALR-2026-0001", FACTS, HYPS, "critical")


def test_unknown_hypothesis_is_rejected():
    bad = doc()
    bad["hypotheses"][1]["id"] = "H9"
    with pytest.raises(ValidationError, match="H9"):
        parse_assessment(json.dumps(bad), "ALR-2026-0001", FACTS, HYPS, "critical")


def test_agreement_flag_must_match_level():
    bad = doc(severity_view={"level": "high", "agrees_with_rubric": True, "explanation": "e"})
    with pytest.raises(ValidationError, match="inconsistent"):
        parse_assessment(json.dumps(bad), "ALR-2026-0001", FACTS, HYPS, "critical")


def test_disagreement_is_allowed_when_stated():
    ok = doc(severity_view={"level": "high", "agrees_with_rubric": False, "explanation": "mail forward unconfirmed"})
    assert parse_assessment(json.dumps(ok), "ALR-2026-0001", FACTS, HYPS, "critical")["severity_view"]["agrees_with_rubric"] is False


def test_needs_an_alternative_explanation():
    with pytest.raises(ValidationError, match="alternative"):
        parse_assessment(json.dumps(doc(alternative_explanations=[])), "ALR-2026-0001", FACTS, HYPS, "critical")


def test_make_assessment_repairs_once(audit):
    outputs = iter(["not json", json.dumps(doc())])
    llm = lambda s, u: (next(outputs), {"provider": "fake"})  # noqa: E731
    alert = {"alert_id": "ALR-2026-0001", "entities": {}}
    plan = {"hypotheses": [{"id": "H1", "description": "d"}, {"id": "H2", "description": "d"}]}
    facts = [{"id": i, "statement": "s", "status": "confirmed", "refs": [], "mock": False} for i in sorted(FACTS)]
    out = make_assessment(alert, plan, facts, [], {"level": "critical", "reasons": []}, {"level": "high", "reasons": []}, llm, audit)
    assert out["alert_id"] == "ALR-2026-0001"
    events = [json.loads(l)["event"] for l in audit.path.read_text().splitlines()]
    assert events.count("assessment_rejected") == 1 and events[-1] == "assessment_validated"
