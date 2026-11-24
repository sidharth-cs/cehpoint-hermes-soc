"""Day 4: the incident report (JSON + Markdown) and the investigation history index.

Everything in the report comes from artifacts already in the run folder: computed facts, tool-call trace,
timeline, the validated assessment and the approval queue. Nothing is re-asked from the model, so the report
cannot contain a claim that is not in the audited run.
"""
import json
from pathlib import Path

from . import correlate
from .audit import utc_now
from .paths import RUNS
from .response import load_requests
from .validation import validate

LIMITATIONS = [
    "The monitored system is a lab portal we own; client IPs are RFC 5737 documentation addresses sent via X-Forwarded-For.",
    "Documentation-range IPs have no public reputation, so IP intel adds context only for public IPs.",
    "Response actions change only the lab portal, and only after a named analyst approves them.",
    "Facts are computed by fixed rules; behaviour outside those rules is reported as unknown, not inferred.",
]


def build_report(alert, calls, timeline, facts, mapping, severity, confidence, assessment, requests, run_dir) -> dict:
    run_dir = Path(run_dir)
    report = {
        "report_id": f"IR-{run_dir.name}",
        "generated_at": utc_now(),
        "alert_id": alert["alert_id"],
        "run_id": run_dir.name,
        "orchestrator": "Hermes Agent (Nous Research) with DeepSeek; read-only `soc` toolset",
        "data_provenance": alert.get("data_provenance", "unknown"),
        "summary": assessment["what_likely_happened"],
        "alert": {k: alert[k] for k in ("rule", "summary", "entities", "created_at") if k in alert},
        "severity": severity,
        "confidence": confidence,
        "model_severity_view": assessment["severity_view"],
        "hypotheses": assessment["hypotheses"],
        "alternative_explanations": assessment["alternative_explanations"],
        "unknowns": assessment["unknowns"],
        "facts": [{k: f[k] for k in ("id", "statement", "status", "refs", "tools", "mock")} for f in facts],
        "attack_mapping": [{k: m[k] for k in ("technique", "name", "fact_ids")} for m in mapping],
        "timeline": correlate.collapse_timeline(timeline),
        "response_actions": requests,
        "tool_calls": [{"seq": c["seq"], "tool": c["tool"], "reason": c["reason"], "ok": c["ok"], "mock": c["mock"],
                        "error": c["error"]["code"] if c.get("error") else None, "duration_ms": c.get("duration_ms")}
                       for c in calls],
        "artifacts": {"audit_log": "audit.jsonl", "tool_trace": "tool_trace.json", "timeline": "timeline.json",
                      "evidence": "evidence.json", "investigation": "investigation.json", "approvals": "approvals.json"},
        "limitations": LIMITATIONS,
    }
    validate(report, "incident_report.schema.json", "incident report")
    return report


def write_report(report: dict, run_dir: Path) -> tuple[Path, Path]:
    run_dir = Path(run_dir)
    js, md = run_dir / "incident_report.json", run_dir / "incident_report.md"
    js.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    md.write_text(render_markdown(report))
    return js, md


def refresh_actions(run_dir: Path) -> None:
    """Re-render the report after an analyst decision so it shows the current approval status."""
    path = Path(run_dir) / "incident_report.json"
    if path.exists():
        report = json.loads(path.read_text())
        report["response_actions"] = load_requests(run_dir)
        write_report(report, run_dir)


def _refs(refs: list[str], n: int = 3) -> str:
    shown = ", ".join(f"`{r}`" for r in refs[:n])
    return shown + (f" (+{len(refs) - n} more)" if len(refs) > n else "") if refs else "none"


def _rule_name(rule) -> str:
    return f"{rule.get('name', '')} ({rule.get('id', '')})" if isinstance(rule, dict) else str(rule or "")


def render_markdown(r: dict) -> str:
    ents = r["alert"].get("entities", {})
    out = [
        f"# Incident report {r['report_id']}",
        "",
        f"> **Data:** {r['data_provenance'].upper()}"
        + (" (synthetic test fixtures, MOCK intel)." if r["data_provenance"] == "synthetic" else
           " (live lab portal log, real ATT&CK data, live intel APIs).")
        + " Response actions apply only to the lab portal, after human approval.",
        "",
        "| | |", "|---|---|",
        f"| Alert | `{r['alert_id']}`: {_rule_name(r['alert'].get('rule'))} |",
        f"| Account | `{ents.get('account', '-')}` |",
        f"| Host | `{ents.get('host', '-')}` |",
        f"| Source IPs | {', '.join(f'`{i}`' for i in ents.get('source_ips', [])) or '-'} |",
        f"| **Severity** | **{r['severity']['level'].upper()}** (how bad if true) |",
        f"| **Confidence** | **{r['confidence']['level'].upper()}** (how sure we are) |",
        f"| Generated | {r['generated_at']} by {r['orchestrator']} |",
        "",
        "## Summary", "", r["summary"], "",
        "## Severity rationale", "", *[f"- {x}" for x in r["severity"]["reasons"]], "",
        f"Model's view: **{r['model_severity_view']['level']}** "
        f"({'agrees' if r['model_severity_view']['agrees_with_rubric'] else 'DISAGREES'} with the rule-based level). "
        + r["model_severity_view"]["explanation"], "",
        "## Confidence rationale", "", *[f"- {x}" for x in r["confidence"]["reasons"]], "",
        "## Hypotheses", "", "| Id | Status | Facts | Explanation |", "|---|---|---|---|",
        *[f"| {h['id']} | {h['status']} | {', '.join(h['fact_ids']) or '-'} | {h['explanation']} |" for h in r["hypotheses"]],
        "",
        "## Alternative explanations", "",
        *[f"- {a['explanation']} [{', '.join(a['fact_ids'])}]. Less likely because: {a['why_less_likely']}"
          for a in r["alternative_explanations"]],
        "",
        "## Still unknown", "", *([f"- {u}" for u in r["unknowns"]] or ["- nothing listed"]), "",
        "## Facts (computed from tool results, not by the model)", "",
        "| Id | Status | Statement | Evidence |", "|---|---|---|---|",
        *[f"| {f['id']} | {f['status']}{' (MOCK)' if f['mock'] else ''} | {f['statement']} | {_refs(f['refs'])} |"
          for f in r["facts"]],
        "",
        "## MITRE ATT&CK (only where a confirmed fact supports it)", "",
        *([f"- **{m['technique']}** {m['name']} <- {', '.join(m['fact_ids'])}" for m in r["attack_mapping"]]
          or ["- none"]),
        "",
        "## Timeline", "", "| Time (UTC) | Count | Event | Account | Source IP | Evidence |", "|---|---|---|---|---|---|",
        *[f"| {t['start'][:19].replace('T', ' ')}{' to ' + t['end'][11:19] if t['count'] > 1 else ''} | {t['count']} "
          f"| {t['event_type']} | {t['account'] or '-'} | {t['src_ip'] or '-'} | {_refs(t['refs'], 1)} |" for t in r["timeline"]],
        "",
        "## Response actions (human approval required)", "",
    ]
    if r["response_actions"]:
        out += ["| Id | Action | Target | Facts | Status | Decided by |", "|---|---|---|---|---|---|"]
        out += [f"| {a['action_id']} | {a['action']} | `{a['target']}` | {', '.join(a['fact_ids'])} | **{a['status']}** "
                f"| {a.get('decided_by', '-')} |" for a in r["response_actions"]]
        out += ["", *[f"- {a['action_id']}: {a['justification']}" for a in r["response_actions"]], "",
                f"Approve with `python -m soc_agent approve runs/{r['run_id']} <id> --analyst <name>` "
                "(interactive terminal only). Actions apply only to the lab portal."]
    else:
        out += ["The agent proposed no disruptive action."]
    out += [
        "", "## Tool-call history", "", "| # | Tool | OK | Reason |", "|---|---|---|---|",
        *[f"| {c['seq']} | {c['tool']}{' (MOCK)' if c['mock'] else ''} | {'yes' if c['ok'] else 'ERROR ' + str(c['error'])} "
          f"| {c['reason']} |" for c in r["tool_calls"]],
        "", "## Audit artifacts (in this run folder)", "", *[f"- {k}: `{v}`" for k, v in r["artifacts"].items()],
        "", "## Limitations", "", *[f"- {x}" for x in r["limitations"]], "",
    ]
    return "\n".join(out)


def append_history(report: dict, runs_dir: Path = RUNS) -> None:
    line = {"ts": report["generated_at"], "run_id": report["run_id"], "alert_id": report["alert_id"],
            "severity": report["severity"]["level"], "confidence": report["confidence"]["level"],
            "actions_requested": len(report["response_actions"])}
    with (Path(runs_dir) / "history.jsonl").open("a") as f:
        f.write(json.dumps(line) + "\n")


def read_history(runs_dir: Path = RUNS) -> list[dict]:
    path = Path(runs_dir) / "history.jsonl"
    rows = [json.loads(x) for x in path.read_text().splitlines() if x.strip()] if path.exists() else []
    for row in rows:  # current approval status comes from the run folder, the source of truth
        reqs = load_requests(Path(runs_dir) / row["run_id"])
        row["actions"] = {s: sum(r["status"] == s for r in reqs) for s in {r["status"] for r in reqs}}
    return rows
