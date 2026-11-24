"""Detection layer (the SIEM's job, not the agent's): watch the live event log and raise alerts automatically.

Rule AUTH-BRUTE-SUCCESS: 10 or more failed logins for one account from one IP within 15 minutes, followed by
a successful login for that account from the same IP. Deterministic, no model involved.
"""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .paths import LAB_STATE
from .tools import data
from .tools.base import DataUnavailable
from .validation import validate

WINDOW = timedelta(minutes=15)
THRESHOLD = 10
RULE = {"id": "AUTH-BRUTE-SUCCESS", "name": "Repeated failed logins followed by success",
        "description": f"{THRESHOLD}+ failed logins for one account from one IP within {int(WINDOW.total_seconds() // 60)} "
                       "minutes, then a successful login for that account from the same IP."}


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def detect(events) -> list[dict]:
    """All rule hits in the events, oldest first, as (account, ip, failures, success) dicts."""
    auth = sorted((e for e in events if e["event_type"] in ("auth_failure", "auth_success")), key=lambda e: e["ts"])
    hits = []
    for s in (e for e in auth if e["event_type"] == "auth_success"):
        t = _ts(s["ts"])
        fails = [f for f in auth if f["event_type"] == "auth_failure" and f.get("account") == s.get("account")
                 and f.get("src_ip") == s.get("src_ip") and t - WINDOW <= _ts(f["ts"]) <= t]  # same-millisecond failures count
        if len(fails) >= THRESHOLD:
            # the window opens at this IP's first attempt on any account, so a spray just before is inside it
            first = min(e["ts"] for e in auth if e.get("src_ip") == s["src_ip"] and t - WINDOW <= _ts(e["ts"]) <= t)
            hits.append({"account": s["account"], "ip": s["src_ip"], "host": s.get("host"), "failures": fails,
                         "success": s, "first_ts": first})
    return hits


def to_alert(alert_id: str, hit: dict) -> dict:
    f, s = hit["failures"], hit["success"]
    alert = {
        "alert_id": alert_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "lab-detector (soc_agent/detect.py)",
        "rule": RULE,
        "severity_hint": "high",
        "entities": {"account": hit["account"], "host": hit["host"], "source_ips": [hit["ip"]], "domains": []},
        "observations": {"failed_logins": len(f), "successful_logins": 1,
                         "window_start": hit["first_ts"][:19] + "Z", "window_end": s["ts"][:19] + "Z"},
        "summary": (f"{len(f)} failed logins for {hit['account']} from {hit['ip']} between {f[0]['ts'][11:19]} and "
                    f"{f[-1]['ts'][11:19]} UTC, then a successful login from the same IP at {s['ts'][11:19]} UTC."),
        "data_provenance": "lab",
    }
    validate(alert, "alert.schema.json", "alert")
    return alert


def _existing(alerts_dir: Path) -> tuple[set, int]:
    keys, n = set(), 0
    for p in alerts_dir.glob("ALR-*.json"):
        a = json.loads(p.read_text())
        keys.add((a["entities"]["account"], a["entities"]["source_ips"][0], a["observations"]["window_end"]))
        n += 1
    return keys, n


def scan(alerts_dir: Path = LAB_STATE / "alerts") -> list[Path]:
    """Writes an alert file for every new rule hit; returns the new files."""
    alerts_dir.mkdir(parents=True, exist_ok=True)
    events, _ = data.load_events()
    keys, n = _existing(alerts_dir)
    new = []
    for hit in detect(events):
        key = (hit["account"], hit["ip"], hit["success"]["ts"][:19] + "Z")
        if key in keys:
            continue
        n += 1
        alert = to_alert(f"ALR-{datetime.now(timezone.utc).year}-{1000 + n}", hit)
        path = alerts_dir / f"{alert['alert_id']}.json"
        path.write_text(json.dumps(alert, indent=2) + "\n")
        keys.add(key)
        new.append(path)
    return new


def watch(on_alert, interval: float = 2.0, once: bool = False) -> None:
    while True:
        try:
            for path in scan():
                on_alert(path)
        except DataUnavailable:
            pass  # portal has not written its log yet
        if once:
            return
        time.sleep(interval)
