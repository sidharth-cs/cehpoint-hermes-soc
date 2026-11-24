"""Day 1: turn a validated alert into a structured, schema-checked investigation plan."""
import json
import re

from .skill import load as _load_skill, with_skill
from .validation import ValidationError, validate

# Tools the agent will be allowed to call from Day 2. On Day 1 they are only named
# in the plan; Hermes has no tools enabled and cannot execute anything.
PLANNED_TOOLS = {
    "search_logs": "Query the lab portal event log by account, host, IP and time window.",
    "lookup_ip": "Reputation and context for an IP from a live public intel API (reserved ranges are not queried).",
    "search_cve": "Look up MITRE ATT&CK techniques (official data) and CVEs (live NVD API).",
    "get_asset_context": "Owner, criticality and role of a host or account from the asset inventory.",
    "none": "A reasoning step that needs no tool (e.g. correlate results already gathered).",
}

QUESTIONS = [
    "Which account and asset are involved?",
    "What is the event timeline, and which events support the alert?",
    "What can be established about the source IP using available, approved intelligence?",
    "Are there related events before or after the successful login?",
    "What severity is justified by the evidence, and what remains unknown?",
    "What containment or remediation steps should a human analyst consider?",
]

SYSTEM_PROMPT = f"""You are the planning stage of a junior SOC analyst agent.
You receive ONE security alert raised by the SIEM. The SIEM already detected it; your job is to plan
how to investigate it with approved tools. You do not execute anything at this stage.

Rules:
- Use only these tools in steps (exact names): {json.dumps(PLANNED_TOOLS, indent=1)}
- Never invent evidence, log lines, IP reputation or CVE details. The plan says what to look for, not what was found.
- Any containment action (block IP, disable account, isolate host, reset password) is NOT a step. List it in
  safety_notes as "requires analyst approval".
- Keep severity assessment for later; the plan only gathers evidence.
- Arguments must only use values present in the alert (account, host, IPs, time window), or time windows
  derived from it, such as a look-back period stated in the alert's rule. Say in the rationale how a window was derived.

Answer these questions through the plan: {json.dumps(QUESTIONS)}

Output ONLY one JSON object, no prose, no markdown fences, with exactly these keys:
alert_id (string), summary (string), hypotheses ([{{"id":"H1","description":...}}]),
steps ([{{"step":1,"objective":...,"tool":<approved tool name>,"arguments":{{...}},"rationale":...,
"evidence_sought":...,"tests_hypotheses":["H1"]}}]), questions ([string]), safety_notes ([string]).
"""


def build_user_prompt(alert: dict) -> str:
    return "Plan the investigation for this alert:\n" + json.dumps(alert, indent=2)


def parse_plan(text: str, alert_id: str) -> dict:
    """Extract and validate the JSON plan from model output. Raises ValidationError with all problems."""
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValidationError("plan", ["no JSON object found in model output"])
    try:
        plan = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValidationError("plan", [f"model output is not valid JSON: {exc}"]) from exc

    validate(plan, "investigation_plan.schema.json", "plan")

    problems = []
    if plan["alert_id"] != alert_id:
        problems.append(f"alert_id {plan['alert_id']!r} does not match alert {alert_id!r}")
    numbers = [s["step"] for s in plan["steps"]]
    if numbers != list(range(1, len(numbers) + 1)):
        problems.append(f"steps must be numbered 1..n in order, got {numbers}")
    hyp_ids = {h["id"] for h in plan["hypotheses"]}
    for s in plan["steps"]:
        unknown = set(s.get("tests_hypotheses", [])) - hyp_ids
        if unknown:
            problems.append(f"step {s['step']} references unknown hypotheses {sorted(unknown)}")
    if problems:
        raise ValidationError("plan", problems)
    return plan


def make_plan(alert: dict, llm, audit, max_repairs: int = 1) -> dict:
    """Ask the LLM (through Hermes) for a plan; on a schema failure, send the errors back once."""
    user = build_user_prompt(alert)
    audit.record("plan_requested", system_prompt=with_skill(SYSTEM_PROMPT), user_prompt=user, skill={k: v for k, v in _load_skill().items() if k != "body"})
    for attempt in range(max_repairs + 1):
        text, meta = llm(with_skill(SYSTEM_PROMPT), user)
        audit.record("llm_response", attempt=attempt, meta=meta, output=text)
        try:
            plan = parse_plan(text, alert["alert_id"])
            audit.record("plan_validated", attempt=attempt, steps=len(plan["steps"]))
            return plan
        except ValidationError as exc:
            audit.record("plan_rejected", attempt=attempt, problems=exc.problems)
            if attempt == max_repairs:
                raise
            user = (
                build_user_prompt(alert)
                + "\n\nYour previous answer was rejected for these reasons:\n- "
                + "\n- ".join(exc.problems)
                + "\nReturn a corrected JSON object only."
            )
    raise AssertionError("unreachable")
