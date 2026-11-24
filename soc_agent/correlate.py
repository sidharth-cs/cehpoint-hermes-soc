"""Day 3: deterministic correlation.

Turns the tool-call trace into (1) a timestamped event timeline and (2) a list of evidence facts.
No language model is involved here, so nothing in the timeline or facts can be invented: every
fact is computed from tool results and cites the log lines / records it came from.

Each fact has a status:
  confirmed     - the evidence shows it
  not_observed  - the relevant data was searched and the thing is absent
  unknown       - the data needed was not searched, or the tool failed (a gap, stated explicitly)
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

BRUTE_FORCE_THRESHOLD = 10          # failed logins for one account before a success counts as brute force
NEW_IP_LOOKBACK = timedelta(days=7)  # minimum look-back that must be searched to call an IP "new"
POST_LOGIN_WINDOW = timedelta(hours=2)
SCRIPTED_AGENTS = ("python-requests", "curl/", "go-http-client", "wget/", "hydra", "okhttp")


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@dataclass
class Fact:
    id: str
    statement: str
    status: str                      # confirmed | not_observed | unknown
    refs: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    mock: bool = False
    data: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- timeline
def build_timeline(calls: list[dict]) -> list[dict]:
    """All events returned by successful search_logs calls, de-duplicated and sorted by time."""
    seen, out = set(), []
    for c in calls:
        if c["tool"] != "search_logs" or not c["ok"] or not c.get("result"):
            continue
        for e in c["result"]["events"]:
            if e["event_id"] in seen:
                continue
            seen.add(e["event_id"])
            out.append(e)
    out.sort(key=lambda e: (e["ts"], e["event_id"]))
    return out


BURST_GAP = timedelta(minutes=5)


def collapse_timeline(timeline: list[dict]) -> list[dict]:
    """Human view: events with the same type/account/IP/host, each within 5 minutes of the previous one,
    become one row with a count, even when other events are interleaved (e.g. a spray hitting several accounts)."""
    rows, open_rows = [], {}
    for e in timeline:
        key = (e["event_type"], e.get("account"), e.get("src_ip"), e.get("host"))
        row = open_rows.get(key)
        if row and _ts(e["ts"]) - _ts(row["end"]) <= BURST_GAP:
            row["count"] += 1
            row["end"] = e["ts"]
            row["refs"].append(e["ref"])
            continue
        row = {"start": e["ts"], "end": e["ts"], "count": 1, "event_type": e["event_type"],
               "account": e.get("account"), "host": e.get("host"), "src_ip": e.get("src_ip"),
               "details": e.get("details") or {}, "refs": [e["ref"]]}
        open_rows[key] = row
        rows.append(row)
    for r in rows:
        r["refs"] = [r["refs"][0], r["refs"][-1]] if r["count"] > 1 else r["refs"]
    return sorted(rows, key=lambda r: r["start"])


# --------------------------------------------------------------------------- coverage helpers
def _searched(calls, **match) -> list[tuple[datetime, datetime]]:
    """Time windows that were successfully searched with (at least) the given filters."""
    wins = []
    for c in calls:
        if c["tool"] != "search_logs" or not c["ok"]:
            continue
        args = c["arguments"]
        if all(args.get(k) == v for k, v in match.items()):
            wins.append((_ts(args["start"]), _ts(args["end"])))
    return wins


def _covers(wins, start: datetime, end: datetime) -> bool:
    return any(s <= start and e >= end for s, e in wins)


def _ok_calls(calls, tool, **match):
    return [c for c in calls if c["tool"] == tool and c["ok"] and all(c["arguments"].get(k) == v for k, v in match.items())]


def _failed(calls, tool):
    return [c for c in calls if c["tool"] == tool and not c["ok"]]


# --------------------------------------------------------------------------- facts
def build_facts(alert: dict, calls: list[dict]) -> list[Fact]:
    account = alert["entities"]["account"]
    host = alert["entities"].get("host")
    ips = alert["entities"].get("source_ips") or []
    ip = ips[0] if ips else None
    obs = alert.get("observations", {})
    w_start = _ts(obs["window_start"]) if obs.get("window_start") else _ts(alert["created_at"]) - timedelta(minutes=30)
    w_end = _ts(obs["window_end"]) if obs.get("window_end") else _ts(alert["created_at"])

    timeline = build_timeline(calls)
    acct_events = [e for e in timeline if e.get("account") == account]
    facts: list[Fact] = []

    # F1 brute force followed by success from the same IP
    fails = [e for e in acct_events if e["event_type"] == "auth_failure" and (not ip or e["src_ip"] == ip)
             and w_start <= _ts(e["ts"]) <= w_end]
    success = next((e for e in acct_events if e["event_type"] == "auth_success" and (not ip or e["src_ip"] == ip)
                    and w_start <= _ts(e["ts"]) <= w_end + timedelta(minutes=1)), None)
    window_searched = _covers(_searched(calls, account=account) + (_searched(calls, src_ip=ip) if ip else []), w_start, w_end)
    if not window_searched:
        facts.append(Fact("F1", f"Login pattern for {account} in the alert window could not be checked "
                                f"(the window was not searched).", "unknown"))
    elif len(fails) >= BRUTE_FORCE_THRESHOLD and success:
        gap = (_ts(success["ts"]) - _ts(fails[-1]["ts"])).total_seconds()
        facts.append(Fact("F1", f"{len(fails)} failed logins for {account} from {ip}, then a successful login from the same IP "
                                f"at {success['ts']} ({int(gap)}s after the last failure).", "confirmed",
                          [fails[0]["ref"], fails[-1]["ref"], success["ref"]], ["search_logs"],
                          data={"failures": len(fails), "success_ts": success["ts"], "first_failure_ts": fails[0]["ts"]}))
    elif len(fails) >= BRUTE_FORCE_THRESHOLD:
        facts.append(Fact("F1", f"{len(fails)} failed logins for {account} from {ip}; no successful login from that IP in the window.",
                          "not_observed", [fails[0]["ref"], fails[-1]["ref"]], ["search_logs"], data={"failures": len(fails)}))
    else:
        facts.append(Fact("F1", f"Only {len(fails)} failed login(s) for {account} in the window "
                                f"(threshold {BRUTE_FORCE_THRESHOLD}); not a brute-force pattern.", "not_observed",
                          [e["ref"] for e in fails[:2]] + ([success["ref"]] if success else []), ["search_logs"],
                          data={"failures": len(fails), "success_ts": success["ts"] if success else None}))
    success_ts = _ts(success["ts"]) if success else w_end

    # F2 source IP new for this account
    lookback = _searched(calls, account=account, src_ip=ip) + _searched(calls, account=account) if ip else []
    needed_start = w_start - NEW_IP_LOOKBACK
    if not ip:
        facts.append(Fact("F2", "Alert names no source IP; IP history not applicable.", "unknown"))
    elif not _covers(lookback, needed_start, w_start):
        facts.append(Fact("F2", f"Whether {ip} is new for {account} is unknown: history before the alert was not searched "
                                f"for at least {NEW_IP_LOOKBACK.days} days.", "unknown"))
    else:
        prior = [e for e in acct_events if e["src_ip"] == ip and _ts(e["ts"]) < w_start]
        earliest = min(s for s, e in lookback if s <= needed_start and e >= w_start)
        if prior:
            facts.append(Fact("F2", f"{ip} was seen for {account} before the alert ({len(prior)} earlier events); not a new IP.",
                              "not_observed", [prior[0]["ref"]], ["search_logs"]))
        else:
            facts.append(Fact("F2", f"{ip} has no history for {account} in the searched look-back "
                                    f"({earliest.date()} to {w_start.date()}): the IP is new for this account.",
                              "confirmed", [], ["search_logs"], data={"lookback_from": earliest.isoformat()}))

    # F3 same IP targeted other accounts (spray / campaign)
    ip_wins = _searched(calls, src_ip=ip) if ip else []
    if not ip or not _covers(ip_wins, w_start, w_end):
        facts.append(Fact("F3", "Activity of the source IP against other accounts was not searched.", "unknown"))
    else:
        others = {}
        for e in timeline:
            if e["src_ip"] == ip and e.get("account") != account and w_start <= _ts(e["ts"]) <= w_end:
                o = others.setdefault(e["account"], {"failures": 0, "successes": 0, "refs": []})
                if e["event_type"] == "auth_failure":
                    o["failures"] += 1
                elif e["event_type"] == "auth_success":
                    o["successes"] += 1
                o["refs"].append(e["ref"])
        if others:
            desc = ", ".join(f"{a} ({v['failures']} failed, {v['successes']} successful)" for a, v in sorted(others.items()))
            facts.append(Fact("F3", f"{ip} also targeted {len(others)} other account(s) in the same window: {desc}.",
                              "confirmed", [v["refs"][0] for v in others.values()], ["search_logs"], data={"accounts": others}))
        else:
            facts.append(Fact("F3", f"No other accounts were targeted by {ip} in the alert window.", "not_observed", [], ["search_logs"]))

    # F4/F5/F6 post-login activity from the same IP
    after_end = success_ts + POST_LOGIN_WINDOW
    post_wins = _searched(calls, account=account) + (_searched(calls, host=host) if host else []) + ip_wins
    if not _covers(post_wins, success_ts, success_ts + timedelta(minutes=30)):
        facts.append(Fact("F4", "Activity after the login was not searched (at least 30 minutes after it is needed).", "unknown"))
        facts.append(Fact("F5", "Mailbox rule changes after the login: unknown (not searched).", "unknown"))
        facts.append(Fact("F6", "File access after the login: unknown (not searched).", "unknown"))
    else:
        post = [e for e in acct_events if success_ts < _ts(e["ts"]) <= after_end and (not ip or e["src_ip"] == ip)
                and e["event_type"] != "auth_failure"]
        kinds = sorted({e["event_type"] for e in post})
        facts.append(Fact("F4", (f"After the login, the same IP session performed: {', '.join(kinds)}." if post
                                 else "No further activity from the same IP after the login in the searched window."),
                          "confirmed" if post else "not_observed", [e["ref"] for e in post], ["search_logs"],
                          data={"event_types": kinds}))
        domain = "@" + account.split("@")[1]
        ext = [e for e in post if e["event_type"] == "mailbox_rule_created"
               and not str((e.get("details") or {}).get("forward_to", "")).endswith(domain)]
        facts.append(Fact("F5", (f"A mailbox rule forwarding mail to an external address ({ext[0]['details'].get('forward_to')}) "
                                 f"was created at {ext[0]['ts']}." if ext else "No external mail-forwarding rule was created."),
                          "confirmed" if ext else "not_observed", [e["ref"] for e in ext], ["search_logs"]))
        files = [e for e in post if e["event_type"] == "file_access"]
        if files:
            d = files[0]["details"]
            facts.append(Fact("F6", f"Files were read from {d.get('share')} ({d.get('files_read')} files, "
                                    f"{d.get('bytes_read')} bytes) at {files[0]['ts']}.", "confirmed",
                              [e["ref"] for e in files], ["search_logs"], data=d))
        else:
            facts.append(Fact("F6", "No file access after the login.", "not_observed", [], ["search_logs"]))

    # F7 scripted client
    logins = fails + ([success] if success else [])
    ua = sorted({(e.get("details") or {}).get("user_agent") for e in logins} - {None})
    scripted = [u for u in ua if any(s in u.lower() for s in SCRIPTED_AGENTS)]
    if not ua:
        facts.append(Fact("F7", "Client user agent not present in the login events.", "unknown"))
    else:
        facts.append(Fact("F7", (f"Logins used a scripted client user agent ({', '.join(scripted)}), not a browser or mail app."
                                 if scripted else f"Login user agents look interactive ({', '.join(ua)})."),
                          "confirmed" if scripted else "not_observed", [logins[0]["ref"]], ["search_logs"]))

    # F8/F9/F10 asset and account context
    acct_ctx = host_ctx = None
    for c in _ok_calls(calls, "get_asset_context"):
        acct_ctx = acct_ctx or c["result"].get("account")
        host_ctx = host_ctx or c["result"].get("host")

    if not acct_ctx or not acct_ctx.get("found"):
        facts.append(Fact("F8", "Account MFA status unknown (no asset context).", "unknown"))
        facts.append(Fact("F9", "Usual login hours/IPs for the account unknown (no asset context).", "unknown"))
    else:
        mfa = acct_ctx.get("mfa_enrolled")
        facts.append(Fact("F8", f"{account} is {'not ' if not mfa else ''}enrolled in MFA"
                                f"{' (a password alone was enough to log in)' if not mfa else ''}.",
                          "confirmed" if mfa is False else "not_observed", [f"data/assets/inventory.json#{account}"],
                          ["get_asset_context"], data={"mfa_enrolled": mfa, "privileged": acct_ctx.get("privileged")}))
        hours, usual_ips = acct_ctx.get("usual_hours_utc"), acct_ctx.get("usual_ips", [])
        off, parts = None, []
        if hours and success:
            h0, h1 = hours.split("-")
            t = _ts(success["ts"]).strftime("%H:%M")
            off = not (h0 <= t <= h1)
            parts.append(f"login at {t} UTC is {'outside' if off else 'inside'} usual hours {hours}")
        if ip:
            parts.append(f"{ip} is {'not ' if ip not in usual_ips else ''}one of the account's usual IPs")
        unusual = bool(off) or (ip is not None and ip not in usual_ips)
        facts.append(Fact("F9", ("; ".join(parts) + ".")[:1].upper() + ("; ".join(parts) + ".")[1:] if parts else "No login to compare with usual behaviour.",
                          "confirmed" if unusual else "not_observed", [f"data/assets/inventory.json#{account}"],
                          ["get_asset_context"], data={"off_hours": off, "usual_ip": (ip in usual_ips) if ip else None}))

    if not host_ctx or not host_ctx.get("found"):
        facts.append(Fact("F10", "Host criticality unknown (no asset context).", "unknown"))
    else:
        facts.append(Fact("F10", f"{host} is a {host_ctx.get('criticality')}-criticality {host_ctx.get('role', 'host')} "
                                 f"({host_ctx.get('department')}).",
                          "confirmed", [f"data/assets/inventory.json#{host}"], ["get_asset_context"],
                          data={"criticality": host_ctx.get("criticality")}))

    # F11 IP reputation (mock)
    reps = _ok_calls(calls, "lookup_ip", ip=ip) if ip else []
    if not reps:
        failed = _failed(calls, "lookup_ip")
        why = f"the lookup failed ({failed[0]['error']['code']})" if failed else "it was not looked up"
        facts.append(Fact("F11", f"Reputation of {ip} is unknown: {why}.", "unknown", tools=["lookup_ip"], mock=True))
    elif not reps[0]["result"]["found"]:
        facts.append(Fact("F11", f"{ip} is not in the (MOCK) intel source; unknown is not benign.", "unknown",
                          tools=["lookup_ip"], mock=True))
    else:
        r = reps[0]["result"]
        bad = r.get("verdict") in ("malicious", "suspicious")
        facts.append(Fact("F11", f"MOCK intel rates {ip} as {r.get('verdict')} (score {r.get('score')}, "
                                 f"tags {', '.join(r.get('tags') or [])}).",
                          "confirmed" if bad else "not_observed", [f"data/intel/ip_reputation_mock.json#{ip}"],
                          ["lookup_ip"], mock=True, data={"verdict": r.get("verdict"), "score": r.get("score")}))
    return facts


# --------------------------------------------------------------------------- ATT&CK mapping (only where evidence justifies it)
def attack_mapping(facts: list[Fact], calls: list[dict]) -> list[dict]:
    by = {f.id: f for f in facts}
    snapshot_ids = {m["id"] for c in _ok_calls(calls, "search_cve") for m in c["result"]["matches"]}
    rules = [
        ("T1110.001", "Brute Force: Password Guessing", ["F1"], by["F1"].data.get("failures", 0) >= BRUTE_FORCE_THRESHOLD),
        ("T1110.003", "Brute Force: Password Spraying", ["F3"], by["F3"].status == "confirmed"),
        ("T1078", "Valid Accounts", ["F1"], by["F1"].status == "confirmed"),
        ("T1114.003", "Email Collection: Email Forwarding Rule", ["F5"], by["F5"].status == "confirmed"),
        ("T1039", "Data from Network Shared Drive", ["F6"], by["F6"].status == "confirmed"),
    ]
    return [{"technique": tid, "name": name, "fact_ids": ids, "in_intel_snapshot": tid in snapshot_ids,
             "justification": " ".join(by[i].statement for i in ids)}
            for tid, name, ids, applies in rules if applies]


# --------------------------------------------------------------------------- severity and confidence (kept separate)
def assess_severity(facts: list[Fact]) -> dict:
    """How bad it is if the evidence is right. Fixed, readable rules over fact statuses."""
    by = {f.id: f for f in facts}
    status = lambda i: by[i].status if i in by else "unknown"  # noqa: E731
    if status("F1") == "confirmed":
        level, reasons = "high", ["F1: brute force followed by a successful login (account access likely obtained)"]
        if status("F5") == "confirmed":
            level = "critical"
            reasons.append("F5: external mail-forwarding rule created after the login")
        if status("F6") == "confirmed" and by["F10"].data.get("criticality") in ("high", "critical"):
            level = "critical"
            reasons.append("F6 + F10: files read from a share using a high-criticality asset")
        if by["F8"].data.get("privileged"):
            level = "critical"
            reasons.append("F8: account is privileged")
    elif by["F1"].data.get("failures", 0) >= BRUTE_FORCE_THRESHOLD:
        level, reasons = "medium", ["F1: repeated failed logins, but no successful login from that IP"]
        if status("F3") == "confirmed":
            reasons.append("F3: same IP targeted other accounts (possible campaign)")
    elif status("F1") == "unknown":
        level, reasons = "medium", ["F1 unknown: the alert could not be checked, so its own severity hint is not downgraded"]
    else:
        level, reasons = "low", ["F1: no brute-force pattern"]
        if status("F9") == "not_observed" and status("F11") != "confirmed":
            reasons.append("F9 + F11: login from a usual IP at usual hours, no bad reputation")
    return {"level": level, "reasons": reasons}


def assess_confidence(facts: list[Fact], calls: list[dict]) -> dict:
    """How sure we are. Separate from severity: driven by gaps, tool failures, conflicts and mock-only evidence."""
    key = ["F1", "F2", "F3", "F4", "F8", "F11"]
    by = {f.id: f for f in facts}
    unknown = [k for k in key if by.get(k) and by[k].status == "unknown"]
    failures = [c for c in calls if not c["ok"]]
    reasons, penalty = [], len(unknown)
    if unknown:
        reasons.append("gaps: " + "; ".join(f"{k} - {by[k].statement}" for k in unknown))
    if failures:
        penalty += 1
        reasons.append(f"{len(failures)} tool call(s) failed: " + ", ".join(f"{c['tool']}={c['error']['code']}" for c in failures))
    if by["F1"].status == "confirmed" and by.get("F9") and by["F9"].status == "not_observed":
        penalty += 1
        reasons.append("conflict: brute-force pattern, yet the login came from a usual IP at usual hours (F1 vs F9)")
    if by.get("F11") and by["F11"].status == "confirmed":
        reasons.append("F11 comes from MOCK intel; it supports the conclusion but is not relied on alone")
    level = "high" if penalty == 0 else "medium" if penalty <= 2 else "low"
    if not unknown and not failures:
        reasons.insert(0, "all key facts were checked and every tool call succeeded")
    return {"level": level, "reasons": reasons}


def facts_as_dicts(facts: list[Fact]) -> list[dict]:
    return [asdict(f) for f in facts]
