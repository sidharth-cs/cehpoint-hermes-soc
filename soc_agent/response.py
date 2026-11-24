"""Day 4: the human approval gate for disruptive response actions.

How the gate works:
- The Hermes agent never gets a response tool. Its only tools are the four read-only `soc` tools, so it cannot
  block or disable anything itself. It can only PROPOSE an action inside its assessment.
- Proposals are checked (known action, target must be an entity of the alert, must cite a confirmed fact), then
  queued in the run folder as `approvals.json` with status `pending_approval`.
- Only a human, from an interactive terminal (`python -m soc_agent approve ...`), can approve. They must type the
  action id and target exactly. Every decision is written to the run's audit log with the analyst's name.
- An approved action is carried out on the lab portal we own (lab/app.py) through its admin API, with an admin
  token only the local user can read. The attacker's next request gets 403. Nothing outside the lab is touched
  (brief section 8: actions only on lab systems, after approval).
"""
import hashlib
import json
import os
from pathlib import Path

import httpx

from .audit import AuditLog, utc_now
from .paths import LAB_STATE

LAB_URL = os.environ.get("LAB_URL", "http://127.0.0.1:8800")
TARGET_SYSTEM = "lab portal LAB-PORTAL-01 (lab/app.py)"

RESPONSE_ACTIONS = {
    "block_ip": "Block all requests from this IP at the lab portal",
    "disable_account": "Disable this account on the lab portal and end its sessions",
}


class GateError(RuntimeError):
    """The approval gate refused. Nothing was executed."""


def _digest(req: dict) -> str:
    core = {k: req[k] for k in ("action_id", "action", "target", "fact_ids", "justification", "requested_by")}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()


def queue_requests(recommended: list[dict], audit: AuditLog) -> list[dict]:
    reqs = []
    for i, a in enumerate(recommended, 1):
        req = {"action_id": f"A{i}", "action": a["action"], "target": a["target"], "fact_ids": a["fact_ids"],
               "justification": a["justification"], "requested_by": "hermes-agent", "requested_at": utc_now(),
               "status": "pending_approval", "target_system": TARGET_SYSTEM}
        req["digest"] = _digest(req)
        reqs.append(req)
    audit.write_artifact("approvals.json", {"run_id": audit.run_id, "requests": reqs})
    audit.record("approval_requested", requests=reqs)
    return reqs


def load_requests(run_dir: Path) -> list[dict]:
    path = Path(run_dir) / "approvals.json"
    return json.loads(path.read_text())["requests"] if path.exists() else []


def decide(run_dir: Path, action_id: str, analyst: str, approve: bool, confirm=input) -> dict:
    """Approve (and carry out the action on the lab portal) or reject one pending request. Raises GateError on refusal."""
    run_dir = Path(run_dir)
    audit = AuditLog.open(run_dir)
    analyst = (analyst or "").strip()
    reqs = load_requests(run_dir)
    req = next((r for r in reqs if r["action_id"] == action_id), None)

    def refuse(why: str):
        audit.record("approval_refused", action_id=action_id, analyst=analyst or None, reason=why)
        raise GateError(why)

    if not analyst or analyst.lower() in {"hermes", "hermes-agent", "agent", "model"}:
        refuse("a named human analyst is required (--analyst)")
    if req is None:
        refuse(f"no request {action_id!r} in this run")
    if req["status"] != "pending_approval":
        refuse(f"{action_id} is already {req['status']}; a decision cannot be changed or repeated")
    if req["action"] not in RESPONSE_ACTIONS:
        refuse(f"unknown action {req['action']!r}")
    if _digest(req) != req.get("digest"):
        refuse(f"{action_id} was modified after it was requested; re-run the investigation")

    if approve:
        expected = f"{req['action_id']} {req['target']}"
        typed = confirm(f'Type "{expected}" to approve {req["action"]} on the lab portal: ').strip()
        if typed != expected:
            refuse("confirmation text did not match; nothing was executed")
        try:
            result = execute_on_lab(req, run_dir.name, analyst)
        except (httpx.HTTPError, FileNotFoundError) as exc:
            refuse(f"approved, but the lab portal could not apply it ({exc}); nothing changed, approve again when it is up")
        audit.record("action_executed", action_id=action_id, action=req["action"], target=req["target"],
                     system=TARGET_SYSTEM, controls=result.get("controls"))
        req["status"] = "executed"
    else:
        req["status"] = "rejected"
    req["decided_by"], req["decided_at"] = analyst, utc_now()

    (run_dir / "approvals.json").write_text(json.dumps({"run_id": run_dir.name, "requests": reqs}, indent=2))
    audit.record("approval_granted" if approve else "approval_rejected", action_id=action_id, action=req["action"],
                 target=req["target"], analyst=analyst)
    return req


def execute_on_lab(req: dict, run_id: str, analyst: str) -> dict:
    """The only code path that changes the lab portal. Called by decide() after a human approved."""
    token = (LAB_STATE / "admin_token").read_text().strip()
    endpoint = {"block_ip": "/admin/block_ip", "disable_account": "/admin/disable_account"}[req["action"]]
    r = httpx.post(LAB_URL + endpoint, headers={"X-Admin-Token": token}, timeout=5,
                   json={"target": req["target"], "action_id": req["action_id"], "approved_by": analyst, "run_id": run_id})
    r.raise_for_status()
    return r.json()
