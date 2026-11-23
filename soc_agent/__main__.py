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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="soc_agent", description="Hermes-powered SOC analyst (Day 1: planning)")
    sub = p.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("plan", help="Validate an alert and produce a structured investigation plan")
    pp.add_argument("alert")
    pp.add_argument("--model", default=None, help="DeepSeek model id (default: $SOC_MODEL or deepseek-chat)")
    pp.add_argument("--show-prompt", action="store_true", help="Print the prompt and exit without calling the model")
    pp.set_defaults(func=cmd_plan)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
