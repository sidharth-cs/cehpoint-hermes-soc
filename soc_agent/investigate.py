"""Day 2: let Hermes gather evidence with the approved `soc` toolset, following the Day 1 plan."""
import json

from . import planner
from .tools import TOOLSET, start_trace, stop_trace
from .tools.specs import ALL_TOOLS
from .skill import with_skill
from .validation import ValidationError, validate

EVIDENCE_PROMPT = f"""You are the evidence-gathering stage of a junior SOC analyst agent.
You have an alert and an investigation plan. Gather evidence by calling the approved tools.

Approved tools (the only ones you have): {", ".join(t.name for t in ALL_TOOLS)}.
Rules:
- Every tool call must include `reason`: one sentence saying why this call is needed.
- Pick tools based on the alert and the plan. Do not call a tool that does not serve a plan step.
- Use only values from the alert, the plan, or earlier tool results. Never invent evidence.
- Every tool result has `ok`. If ok is false, record the error code in tool_failures and continue
  with the other evidence; do not retry the same failing call more than once.
- Every tool result says `mock` and `source`. Copy `mock` into each finding; never present mock data as live intelligence.
- Cite evidence: put event refs (e.g. lab/state/events.jsonl#L172) or record ids in `refs`.
- Do not assign severity and do not recommend or take containment actions. That comes later.

When you have enough evidence, reply with ONLY one JSON object, no markdown:
{{"alert_id": ..., "evidence": [{{"tool": ..., "finding": ..., "refs": [...], "mock": true|false}}],
  "tool_failures": [string], "open_questions": [string]}}
"""


def parse_evidence(text: str, alert_id: str, mock_tools: set[str] | None = None) -> dict:
    cleaned = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValidationError("evidence", ["no JSON object in final answer"])
    try:
        doc = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValidationError("evidence", [f"final answer is not valid JSON: {exc}"]) from exc
    validate(doc, "evidence_report.schema.json", "evidence")
    if doc["alert_id"] != alert_id:
        raise ValidationError("evidence", [f"alert_id {doc['alert_id']!r} does not match {alert_id!r}"])
    for item in doc["evidence"]:
        if item["tool"] in (mock_tools if mock_tools is not None else {"lookup_ip", "search_cve"}) and not item["mock"]:
            raise ValidationError("evidence", [f"finding from {item['tool']} must be marked mock=true"])
    return doc


REPAIR_PROMPT = (
    "Your last message was rejected: {problems}. It was neither a real tool call nor the final JSON report. "
    "If you still need evidence, call the tool through a proper function call (do not write the call as text "
    "or XML). Otherwise reply with ONLY the final JSON object described in your instructions."
)


def gather_evidence(alert: dict, plan: dict, agent, audit, max_repairs: int = 2) -> tuple[dict, list[dict]]:
    """Runs a tool-enabled Hermes agent. Returns (evidence report, tool-call trace).

    Models sometimes end a turn with a tool call written as plain text instead of a real function call, or with
    prose instead of JSON. When the final answer fails validation, the SAME conversation continues with the
    rejection reasons (so gathered evidence is not lost), up to `max_repairs` times.
    """
    user = ("Alert:\n" + json.dumps(alert, indent=2) + "\n\nInvestigation plan:\n" + json.dumps(plan, indent=2))
    audit.record("evidence_requested", system_prompt=with_skill(EVIDENCE_PROMPT), user_prompt=user,
                 enabled_toolsets=[TOOLSET], tools=sorted(agent.valid_tool_names))
    trace = start_trace(audit)
    history = None
    try:
        for attempt in range(max_repairs + 1):
            result = agent.run_conversation(user_message=user, system_message=with_skill(EVIDENCE_PROMPT),
                                            conversation_history=history)
            text = result.get("final_response") or ""
            audit.record("llm_response", stage="evidence", attempt=attempt, output=text,
                         api_calls=result.get("api_calls"), failed=bool(result.get("failed")), error=result.get("error"))
            if result.get("failed"):
                raise RuntimeError(f"Hermes run failed: {result.get('error')}")
            try:
                report = parse_evidence(text, alert["alert_id"], {c["tool"] for c in trace.calls if c["mock"]})
            except ValidationError as exc:
                audit.record("evidence_rejected", attempt=attempt, problems=exc.problems)
                if attempt == max_repairs:
                    raise
                history = result.get("messages")
                user = REPAIR_PROMPT.format(problems="; ".join(exc.problems))
                continue
            audit.record("evidence_validated", attempt=attempt, findings=len(report["evidence"]),
                         tool_calls=len(trace.calls))
            return report, trace.calls
    finally:
        stop_trace()
    raise AssertionError("unreachable")
