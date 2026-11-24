"""Day 3: the model's assessment of the computed facts (Hermes, no tools).

The model never sees raw logs here, only the facts computed by correlate.py, each with an id, a status
(confirmed / not_observed / unknown) and its evidence refs. It must cite fact ids for every claim, and
citations of facts that do not exist are rejected. Severity and confidence stay with the rubric; the model
states whether it agrees and why, and any disagreement is shown in the report rather than silently applied.
"""
import json

from .skill import with_skill
from .validation import ValidationError, validate

# Facts that indicate hostile activity. A disruptive proposal must rest on at least one of these being CONFIRMED;
# context facts (host criticality, MFA status, usual hours) can never justify blocking or disabling on their own.
ACTION_EVIDENCE = {"F1", "F3", "F5", "F7"}  # brute force+success, spray, external forwarding, scripted client

ASSESS_PROMPT = """You are the assessment stage of a junior SOC analyst agent.
You receive an alert, the investigation hypotheses, a list of FACTS computed from tool results, an ATT&CK mapping,
and a rule-based severity and confidence. You did not see the raw logs; the facts are your only evidence.

Rules:
- Every claim must cite fact ids (e.g. ["F1","F5"]). Do not cite anything that is not in the facts list.
- A fact with status "unknown" is a gap: never treat it as confirmed. A fact with status "not_observed" was searched and absent.
- Facts marked mock=true come from test data: you may use them as supporting evidence only, never as the sole basis.
- For each hypothesis decide: supported, refuted or undetermined, with the facts that decide it.
- Give at least one alternative (benign or different) explanation and say which facts make it less likely.
- List what remains unknown.
- Severity is how bad it is if true; confidence is how sure we are. Do not mix them.
- severity_view: give your own level and say whether you agree with the rule-based severity, and why.
- You cannot take any action. You MAY propose disruptive response actions in recommended_actions: block_ip (only an
  alert source IP) or disable_account (only the alert account), each citing CONFIRMED threat facts (F1, F3, F5, F7). Every proposal is queued
  for a human analyst who approves or rejects it. Propose nothing if confirmed evidence does not justify it.

Reply with ONLY one JSON object, no markdown:
{"alert_id": ..., "what_likely_happened": ..., "hypotheses": [{"id": "H1", "status": ..., "fact_ids": [...], "explanation": ...}],
 "alternative_explanations": [{"explanation": ..., "fact_ids": [...], "why_less_likely": ...}],
 "unknowns": [...], "severity_view": {"level": ..., "agrees_with_rubric": true|false, "explanation": ...},
 "recommended_actions": [{"action": "block_ip"|"disable_account", "target": ..., "fact_ids": [...], "justification": ...}]}
"""


def build_user_prompt(alert, plan, facts, mapping, severity, confidence) -> str:
    return json.dumps({
        "alert": {k: alert[k] for k in ("alert_id", "rule", "entities", "observations", "summary") if k in alert},
        "hypotheses": plan["hypotheses"],
        "facts": [{k: f[k] for k in ("id", "statement", "status", "refs", "mock")} for f in facts],
        "attack_mapping": [{k: m[k] for k in ("technique", "name", "fact_ids")} for m in mapping],
        "rule_based_severity": severity,
        "rule_based_confidence": confidence,
    }, indent=2)


def action_targets(alert: dict) -> dict[str, set[str]]:
    """The only targets a proposal may name: entities from the validated alert, never values the model invents."""
    ents = alert.get("entities", {})
    return {"block_ip": set(ents.get("source_ips", [])), "disable_account": {ents["account"]} if ents.get("account") else set()}


def parse_assessment(text: str, alert_id: str, fact_ids: set[str], hypothesis_ids: set[str], rubric_level: str,
                     confirmed_ids: set[str] | None = None, targets: dict[str, set[str]] | None = None) -> dict:
    cleaned = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValidationError("assessment", ["no JSON object in the answer"])
    try:
        doc = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValidationError("assessment", [f"not valid JSON: {exc}"]) from exc
    validate(doc, "assessment.schema.json", "assessment")

    problems = []
    if doc["alert_id"] != alert_id:
        problems.append(f"alert_id {doc['alert_id']!r} does not match {alert_id!r}")
    cited = [f for h in doc["hypotheses"] for f in h["fact_ids"]] + [f for a in doc["alternative_explanations"] for f in a["fact_ids"]]
    unknown_ids = sorted(set(cited) - fact_ids)
    if unknown_ids:
        problems.append(f"cites facts that do not exist: {unknown_ids}")
    bad_h = sorted({h["id"] for h in doc["hypotheses"]} - hypothesis_ids)
    if bad_h:
        problems.append(f"unknown hypothesis ids: {bad_h}")
    for h in doc["hypotheses"]:
        if h["status"] != "undetermined" and not h["fact_ids"]:
            problems.append(f"{h['id']} is {h['status']} but cites no facts")
    if not doc["alternative_explanations"]:
        problems.append("give at least one alternative explanation")
    if doc["severity_view"]["agrees_with_rubric"] != (doc["severity_view"]["level"] == rubric_level):
        problems.append("severity_view.agrees_with_rubric is inconsistent with the level given")
    doc.setdefault("recommended_actions", [])
    for a in doc["recommended_actions"]:
        if targets is not None and a["target"] not in targets.get(a["action"], set()):
            problems.append(f"{a['action']} target {a['target']!r} is not an entity of this alert")
        if not set(a["fact_ids"]) <= fact_ids:
            problems.append(f"{a['action']} cites facts that do not exist: {sorted(set(a['fact_ids']) - fact_ids)}")
        elif confirmed_ids is not None and not set(a["fact_ids"]) & confirmed_ids:
            problems.append(f"{a['action']} {a['target']} cites no confirmed threat fact (F1, F3, F5 or F7)")
    if problems:
        raise ValidationError("assessment", problems)
    return doc


def make_assessment(alert, plan, facts, mapping, severity, confidence, llm, audit, max_repairs: int = 1) -> dict:
    user = build_user_prompt(alert, plan, facts, mapping, severity, confidence)
    ids = {f["id"] for f in facts}
    hyp_ids = {h["id"] for h in plan["hypotheses"]}
    audit.record("assessment_requested", system_prompt=with_skill(ASSESS_PROMPT), user_prompt=user)
    for attempt in range(max_repairs + 1):
        text, meta = llm(with_skill(ASSESS_PROMPT), user)
        audit.record("llm_response", stage="assessment", attempt=attempt, meta=meta, output=text)
        try:
            doc = parse_assessment(text, alert["alert_id"], ids, hyp_ids, severity["level"],
                                   confirmed_ids={f["id"] for f in facts if f["status"] == "confirmed"} & ACTION_EVIDENCE,
                                   targets=action_targets(alert))
            audit.record("assessment_validated", attempt=attempt)
            return doc
        except ValidationError as exc:
            audit.record("assessment_rejected", attempt=attempt, problems=exc.problems)
            if attempt == max_repairs:
                raise
            user = (build_user_prompt(alert, plan, facts, mapping, severity, confidence)
                    + "\n\nYour previous answer was rejected:\n- " + "\n- ".join(exc.problems)
                    + "\nReturn a corrected JSON object only.")
    raise AssertionError("unreachable")
