"""CLI entry point.

  python -m soc_agent plan data/alerts/ALR-2026-0001.json
  python -m soc_agent plan data/alerts/ALR-2026-0001.json --show-prompt   # no API call
"""
import argparse
import json
import sys

from . import correlate, planner
from .assess import make_assessment
from .audit import AuditLog
from .validation import ValidationError, load_alert


def cmd_plan(args) -> int:
    try:
        alert = load_alert(args.alert)
    except ValidationError as exc:
        print(f"Rejected alert: {exc}", file=sys.stderr)
        return 2

    if args.show_prompt:
        print("=== SYSTEM ===\n" + planner.SYSTEM_PROMPT + "\n=== USER ===\n" + planner.build_user_prompt(alert))
        return 0

    from .hermes_runtime import MissingCredentials, hermes_llm

    audit = AuditLog(alert["alert_id"])
    audit.record("alert_received", alert=alert, source_file=str(args.alert))
    try:
        llm = hermes_llm(model=args.model)
        plan = planner.make_plan(alert, llm, audit)
    except MissingCredentials as exc:
        audit.record("error", kind="missing_credentials", message=str(exc))
        print(exc, file=sys.stderr)
        return 3
    except (ValidationError, RuntimeError) as exc:
        audit.record("error", kind=type(exc).__name__, message=str(exc))
        print(f"Planning failed: {exc}\nAudit log: {audit.path}", file=sys.stderr)
        return 4

    out = audit.write_artifact("plan.json", plan)
    audit.record("run_complete", plan_file=str(out))
    print(f"Alert {alert['alert_id']}: {plan['summary']}\n")
    for h in plan["hypotheses"]:
        print(f"  {h['id']}: {h['description']}")
    print()
    for s in plan["steps"]:
        print(f"  {s['step']:>2}. [{s['tool']}] {s['objective']}  args={json.dumps(s['arguments'])}")
    print("\nNeeds analyst approval / must not do:")
    for n in plan["safety_notes"]:
        print(f"  - {n}")
    print(f"\nPlan: {out}\nAudit log: {audit.path}")
    return 0


def cmd_investigate(args) -> int:
    try:
        alert = load_alert(args.alert)
    except ValidationError as exc:
        print(f"Rejected alert: {exc}", file=sys.stderr)
        return 2
    from .hermes_runtime import MissingCredentials, build_agent, hermes_llm
    from .investigate import gather_evidence

    audit = AuditLog(alert["alert_id"])
    audit.record("alert_received", alert=alert, source_file=str(args.alert))
    try:
        plan = planner.make_plan(alert, hermes_llm(model=args.model), audit)
        audit.write_artifact("plan.json", plan)
        print(f"Plan: {len(plan['steps'])} steps. Gathering evidence with the approved tools...\n")
        agent = build_agent(enabled_toolsets=["soc"], model=args.model, max_iterations=14)
        report, calls = gather_evidence(alert, plan, agent, audit)
        audit.write_artifact("tool_trace.json", {"alert_id": alert["alert_id"], "calls": calls})
        audit.write_artifact("evidence.json", report)

        # Day 3: deterministic correlation, then the model's assessment of the computed facts
        timeline = correlate.build_timeline(calls)
        fact_objs = correlate.build_facts(alert, calls)
        facts = correlate.facts_as_dicts(fact_objs)
        mapping = correlate.attack_mapping(fact_objs, calls)
        severity = correlate.assess_severity(fact_objs)
        confidence = correlate.assess_confidence(fact_objs, calls)
        audit.record("correlation_complete", timeline_events=len(timeline), facts=facts, attack_mapping=mapping,
                     severity=severity, confidence=confidence)
        assessment = make_assessment(alert, plan, facts, mapping, severity, confidence, hermes_llm(model=args.model), audit)
    except MissingCredentials as exc:
        print(exc, file=sys.stderr)
        return 3
    except (ValidationError, RuntimeError) as exc:
        audit.record("error", kind=type(exc).__name__, message=str(exc))
        print(f"Investigation failed: {exc}\nAudit log: {audit.path}", file=sys.stderr)
        return 4

    audit.write_artifact("timeline.json", {"alert_id": alert["alert_id"], "events": timeline})
    audit.write_artifact("investigation.json", {
        "alert_id": alert["alert_id"], "facts": facts, "attack_mapping": mapping,
        "severity": severity, "confidence": confidence, "assessment": assessment})
    audit.record("run_complete")
    _print_investigation(alert, calls, timeline, facts, mapping, severity, confidence, assessment)
    print(f"\nRun folder: {audit.dir}")
    return 0


def _print_investigation(alert, calls, timeline, facts, mapping, severity, confidence, assessment) -> None:
    from datetime import datetime, timedelta

    print("Tool calls:")
    for c in calls:
        status = "ok" if c["ok"] else f"ERROR {c['error']['code']}"
        print(f"  {c['seq']:>2}. {c['tool']}{' [MOCK]' if c['mock'] else ''} -> {status}  why: {c['reason']}")

    obs = alert.get("observations", {})
    ts = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))  # noqa: E731
    lo = ts(obs.get("window_start", alert["created_at"])) - timedelta(hours=1)
    hi = ts(obs.get("window_end", alert["created_at"])) + timedelta(hours=2)
    print(f"\nTimeline ({lo:%H:%M}-{hi:%H:%M} UTC around the alert; full timeline in timeline.json):")
    for r in correlate.collapse_timeline([e for e in timeline if lo <= ts(e["ts"]) <= hi]):
        span = r["start"][11:19] + (f"-{r['end'][11:19]}" if r["count"] > 1 else "")
        times = f"{r['count']:>3}x" if r["count"] > 1 else "    "
        extra = {k: v for k, v in r["details"].items() if k in ("forward_to", "share", "files_read")}
        print(f"  {span:<17} {times} {r['event_type']:<21} {r['account']:<22} {r['src_ip']:<15} {r['refs'][0]}"
              + (f"  {extra}" if extra else ""))

    print("\nFacts (computed from tool results, not by the model):")
    mark = {"confirmed": "CONFIRMED", "not_observed": "NOT SEEN ", "unknown": "UNKNOWN  "}
    for f in facts:
        print(f"  {f['id']:<4}{mark[f['status']]} {'[MOCK] ' if f['mock'] else ''}{f['statement']}")

    if mapping:
        print("\nMITRE ATT&CK (only where a confirmed fact justifies it):")
        for m in mapping:
            print(f"  {m['technique']:<10} {m['name']}  <- {', '.join(m['fact_ids'])}")

    print(f"\nSEVERITY:   {severity['level'].upper()}")
    for r in severity["reasons"]:
        print(f"  - {r}")
    print(f"CONFIDENCE: {confidence['level'].upper()}  (how sure we are, separate from severity)")
    for r in confidence["reasons"]:
        print(f"  - {r}")

    print("\nAssessment (Hermes, citing fact ids):")
    print(f"  {assessment['what_likely_happened']}")
    for h in assessment["hypotheses"]:
        print(f"  {h['id']} {h['status'].upper():<12} [{', '.join(h['fact_ids'])}] {h['explanation']}")
    print("  Alternative explanations:")
    for a in assessment["alternative_explanations"]:
        print(f"   - {a['explanation']} [{', '.join(a['fact_ids'])}] Less likely because: {a['why_less_likely']}")
    if assessment["unknowns"]:
        print("  Still unknown:")
        for u in assessment["unknowns"]:
            print(f"   - {u}")
    sv = assessment["severity_view"]
    print(f"  Model's severity view: {sv['level']} ({'agrees' if sv['agrees_with_rubric'] else 'DISAGREES'} "
          f"with the rule-based {severity['level']}): {sv['explanation']}")


def cmd_tools(args) -> int:
    from .tools.specs import ALL_TOOLS
    for t in ALL_TOOLS:
        print(f"{t.name}  ({'MOCK ' if t.mock else ''}source: {t.source}, timeout {t.timeout_s}s)")
        print(f"  {t.description}")
        if args.schemas:
            print("  parameters: " + json.dumps(t.parameters, indent=2).replace("\n", "\n  "))
        print()
    return 0


def cmd_call(args) -> int:
    from .tools import run_tool
    try:
        params = json.loads(args.json_args)
    except json.JSONDecodeError as exc:
        print(f"arguments are not valid JSON: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run_tool(args.tool, params), indent=2, default=str))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="soc_agent", description="Hermes-powered SOC analyst (Day 1: planning)")
    sub = p.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("plan", help="Validate an alert and produce a structured investigation plan")
    pp.add_argument("alert")
    pp.add_argument("--model", default=None, help="DeepSeek model id (default: $SOC_MODEL or deepseek-chat)")
    pp.add_argument("--show-prompt", action="store_true", help="Print the prompt and exit without calling the model")
    pp.set_defaults(func=cmd_plan)
    pi = sub.add_parser("investigate", help="Plan, then gather evidence with the approved tools (Day 2)")
    pi.add_argument("alert")
    pi.add_argument("--model", default=None)
    pi.set_defaults(func=cmd_investigate)
    pt = sub.add_parser("tools", help="List the approved tools")
    pt.add_argument("--schemas", action="store_true", help="Also print each tool's JSON schema")
    pt.set_defaults(func=cmd_tools)
    pc = sub.add_parser("call", help="Run one tool directly with JSON arguments (no model involved)")
    pc.add_argument("tool")
    pc.add_argument("json_args")
    pc.set_defaults(func=cmd_call)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
