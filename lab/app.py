"""Lab portal: a small system we own, used as the target for the test attack.

    .venv/bin/python -m uvicorn lab.app:app --port 8800

It is a login portal with a mailbox-rule API and a payables file share. Every request is written to
lab/state/events.jsonl, the live log the SOC agent investigates. Blocked IPs and disabled accounts in
lab/state/controls.json are enforced on every request; they can only be changed through /admin with the
admin token in lab/state/admin_token (created at start-up, readable only by the local user). The SOC agent
has no tool that reaches this API; only the human approval command does.

All traffic in the lab comes from localhost, so the portal behaves as if it sat behind a reverse proxy and
takes the client IP from X-Forwarded-For. The lab uses RFC 5737 documentation addresses for clients.
"""
import hmac
import html
import json
import os
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

LAB = Path(__file__).resolve().parent
STATE = Path(os.environ.get("LAB_STATE_DIR", LAB / "state"))
HOST = "LAB-PORTAL-01"
SHARE = r"\\LAB-PORTAL-01\payables"
FILES = {f"invoice_2026_{n:03d}.pdf": 180_000 + n * 7_919 for n in range(1, 15)}

USERS = {k: v for k, v in json.loads((LAB / "test_credentials.json").read_text()).items() if not k.startswith("_")}
INVENTORY = json.loads((LAB / "inventory.json").read_text())["accounts"]

_lock = threading.Lock()
_sessions: dict[str, str] = {}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _state_file(name: str) -> Path:
    STATE.mkdir(parents=True, exist_ok=True)
    return STATE / name


def log(event_type: str, account: str | None, ip: str, request: Request, **details) -> None:
    details = {"user_agent": request.headers.get("user-agent"), **details}
    line = {"event_id": f"EVT-{uuid.uuid4().hex[:12]}", "ts": _now(), "event_type": event_type, "account": account,
            "host": HOST, "src_ip": ip, "details": details}
    with _lock, _state_file("events.jsonl").open("a") as f:
        f.write(json.dumps(line) + "\n")


def controls() -> dict:
    p = _state_file("controls.json")
    return json.loads(p.read_text()) if p.exists() else {"blocked_ips": [], "disabled_accounts": []}


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    return xff.split(",")[0].strip() if xff else request.client.host


@asynccontextmanager
async def lifespan(_app):
    p = _state_file("admin_token")          # only the local user can read it; the SOC agent has no file tools
    if not p.exists():
        p.write_text(secrets.token_urlsafe(32))
        p.chmod(0o600)
    yield


app = FastAPI(title="Cehpoint Lab Portal", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.middleware("http")
async def enforce_blocklist(request: Request, call_next):
    ip = client_ip(request)
    if not request.url.path.startswith("/admin") and ip in {b["target"] for b in controls()["blocked_ips"]}:
        log("blocked_request", None, ip, request, path=request.url.path)
        return JSONResponse({"detail": f"{ip} is blocked by a SOC response action"}, status_code=403)
    return await call_next(request)


class Login(BaseModel):
    username: str
    password: str
    otp: str | None = None


@app.post("/login")
def login(body: Login, request: Request):
    ip, user = client_ip(request), body.username
    if user in {d["target"] for d in controls()["disabled_accounts"]}:
        log("auth_failure", user, ip, request, reason="account_disabled")
        raise HTTPException(403, "account disabled")
    creds = USERS.get(user)
    if not creds or not hmac.compare_digest(creds["password"], body.password):
        log("auth_failure", user, ip, request, reason="unknown_user" if not creds else "bad_password")
        raise HTTPException(401, "invalid credentials")
    mfa = INVENTORY.get(user, {}).get("mfa_enrolled", False)
    if mfa and not hmac.compare_digest(creds.get("otp", ""), body.otp or ""):
        log("auth_failure", user, ip, request, reason="mfa_failed")
        raise HTTPException(401, "invalid one-time code")
    token = secrets.token_urlsafe(16)
    _sessions[token] = user
    log("auth_success", user, ip, request, method="password", mfa="passed" if mfa else "not_enrolled")
    return {"token": token}


def _user(authorization: str | None) -> str:
    user = _sessions.get((authorization or "").removeprefix("Bearer "))
    if not user or user in {d["target"] for d in controls()["disabled_accounts"]}:
        raise HTTPException(401, "not logged in")
    return user


class MailRule(BaseModel):
    name: str
    forward_to: str


@app.post("/mail/rules")
def create_rule(body: MailRule, request: Request, authorization: str | None = Header(None)):
    user = _user(authorization)
    log("mailbox_rule_created", user, client_ip(request), request, rule_name=body.name, forward_to=body.forward_to)
    return {"ok": True}


@app.get("/files/payables")
def list_files(authorization: str | None = Header(None)):
    _user(authorization)
    return {"share": SHARE, "files": sorted(FILES)}


class Download(BaseModel):
    names: list[str]


@app.post("/files/payables/download")
def download(body: Download, request: Request, authorization: str | None = Header(None)):
    user = _user(authorization)
    names = [n for n in body.names if n in FILES]
    log("file_access", user, client_ip(request), request, share=SHARE, files_read=len(names),
        bytes_read=sum(FILES[n] for n in names))
    return {"files": names}


@app.post("/logout")
def logout(request: Request, authorization: str | None = Header(None)):
    user = _user(authorization)
    _sessions.pop((authorization or "").removeprefix("Bearer "), None)
    log("logout", user, client_ip(request), request)
    return {"ok": True}


# ---- response actions: reachable only with the admin token (used by `soc_agent approve`) ----
class Action(BaseModel):
    target: str
    action_id: str
    approved_by: str
    run_id: str


def _admin(token: str | None) -> None:
    expected = _state_file("admin_token").read_text().strip()
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(401, "admin token required")


def _apply(kind: str, body: Action, request: Request, token: str | None) -> dict:
    _admin(token)
    with _lock:
        c = controls()
        if body.target not in {x["target"] for x in c[kind]}:
            c[kind].append({"target": body.target, "action_id": body.action_id, "approved_by": body.approved_by,
                            "run_id": body.run_id, "at": _now()})
            _state_file("controls.json").write_text(json.dumps(c, indent=2))
    if kind == "disabled_accounts":
        for t in [t for t, u in _sessions.items() if u == body.target]:
            _sessions.pop(t)
    log("response_action", None, client_ip(request), request, action=kind, target=body.target,
        approved_by=body.approved_by, action_id=body.action_id, run_id=body.run_id)
    return {"ok": True, "controls": controls()}


@app.post("/admin/block_ip")
def block_ip(body: Action, request: Request, x_admin_token: str | None = Header(None)):
    return _apply("blocked_ips", body, request, x_admin_token)


@app.post("/admin/disable_account")
def disable_account(body: Action, request: Request, x_admin_token: str | None = Header(None)):
    return _apply("disabled_accounts", body, request, x_admin_token)


@app.get("/admin/controls")
def get_controls(x_admin_token: str | None = Header(None)):
    _admin(x_admin_token)
    return controls()


@app.get("/health")
def health():
    return {"ok": True, "host": HOST}


@app.get("/", response_class=HTMLResponse)
def status_page():
    """Read-only live view for the demo: recent events and active response controls. Refreshes every 2 s."""
    p = _state_file("events.jsonl")
    lines = p.read_text().splitlines()[-25:] if p.exists() else []
    rows = []
    for line in reversed(lines):
        e = json.loads(line)
        d = {k: v for k, v in (e.get("details") or {}).items() if k != "user_agent"}
        bad = e["event_type"] in ("auth_failure", "blocked_request", "mailbox_rule_created", "file_access")
        rows.append(f"<tr class='{'bad' if bad else ''}'><td>{e['ts'][11:23]}</td><td>{e['event_type']}</td>"
                    f"<td>{html.escape(e.get('account') or '-')}</td><td>{e['src_ip']}</td>"
                    f"<td>{html.escape(json.dumps(d)) if d else ''}</td></tr>")
    c = controls()
    ctl = "".join(f"<li>BLOCKED IP <b>{x['target']}</b> (approved by {html.escape(x['approved_by'])}, {x['action_id']})</li>"
                  for x in c["blocked_ips"]) + "".join(
                  f"<li>DISABLED <b>{html.escape(x['target'])}</b> (approved by {html.escape(x['approved_by'])}, {x['action_id']})</li>"
                  for x in c["disabled_accounts"]) or "<li>none</li>"
    return f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=2><title>Lab Portal</title>
<style>body{{font:14px -apple-system,sans-serif;margin:24px;background:#0f1115;color:#e6e6e6}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:4px 8px;border-bottom:1px solid #2a2d35;text-align:left}}
tr.bad td{{color:#ff8a80}}h1{{font-size:20px}}h2{{font-size:15px;margin-top:20px}}.ctl li{{color:#ffd54f}}</style>
<h1>{HOST} &mdash; lab portal (system we own)</h1>
<p>Live view of <code>lab/state/events.jsonl</code>. Read-only. Refreshes every 2 seconds.</p>
<h2>Active SOC response controls</h2><ul class=ctl>{ctl}</ul>
<h2>Last {len(rows)} events (newest first)</h2>
<table><tr><th>time (UTC)</th><th>event</th><th>account</th><th>source IP</th><th>details</th></tr>{''.join(rows)}</table>"""
