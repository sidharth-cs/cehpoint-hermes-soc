"""CLI entry point.

  python -m soc_agent plan data/alerts/ALR-2026-0001.json
  python -m soc_agent plan data/alerts/ALR-2026-0001.json --show-prompt   # no API call
"""
import argparse
import json
import sys

from . import planner
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
    except MissingCredentials as exc:
        print(exc, file=sys.stderr)
        return 3
    except (ValidationError, RuntimeError) as exc:
        audit.record("error", kind=type(exc).__name__, message=str(exc))
        print(f"Investigation failed: {exc}\nAudit log: {audit.path}", file=sys.stderr)
        return 4

    audit.write_artifact("tool_trace.json", {"alert_id": alert["alert_id"], "calls": calls})
    audit.write_artifact("evidence.json", report)
    audit.record("run_complete")
    print("Tool calls (in order):")
    for c in calls:
        status = "ok" if c["ok"] else f"ERROR {c['error']['code']}"
        mock = " [MOCK]" if c["mock"] else ""
        print(f"  {c['seq']:>2}. {c['tool']}{mock} -> {status} ({c['result_summary']}, {c['duration_ms']} ms)")
        print(f"      why: {c['reason']}")
        print(f"      args: {json.dumps(c['arguments'])}")
    print("\nEvidence:")
    for e in report["evidence"]:
        print(f"  - [{e['tool']}{' MOCK' if e['mock'] else ''}] {e['finding']}")
        if e["refs"]:
            print(f"      refs: {', '.join(e['refs'][:6])}{' ...' if len(e['refs']) > 6 else ''}")
    if report["tool_failures"]:
        print("\nTool failures:")
        for f in report["tool_failures"]:
            print(f"  - {f}")
    print("\nOpen questions:")
    for q in report["open_questions"]:
        print(f"  - {q}")
    print(f"\nRun folder: {audit.dir}")
    return 0


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
