"""The four approved, read-only SOC tools."""
import ipaddress
from collections import Counter
from datetime import datetime, timedelta

from . import data
from .base import REASON, ToolInputError, ToolSpec

MAX_WINDOW = timedelta(days=31)
EVENT_TYPES = ["auth_failure", "auth_success", "logout", "mailbox_rule_created", "file_access"]
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _ts(value: str) -> datetime:
    # jsonschema only enforces "date-time" when an optional package is installed, so check here too.
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ToolInputError(f"{value!r} is not an ISO-8601 date-time, e.g. 2026-11-23T02:58:05Z") from exc
    if parsed.tzinfo is None:
        raise ToolInputError(f"{value!r} has no timezone; use UTC with a trailing Z")
    return parsed


# --------------------------------------------------------------------------- search_logs
def _search_logs(args: dict) -> dict:
    if not any(args.get(k) for k in ("account", "host", "src_ip")):
        raise ToolInputError("give at least one of account, host or src_ip (no unbounded log dumps)")
    start, end = _ts(args["start"]), _ts(args["end"])
    if end <= start:
        raise ToolInputError("end must be after start")
    if end - start > MAX_WINDOW:
        raise ToolInputError("time window is limited to 31 days")
    limit = args.get("limit", 100)
    types = set(args.get("event_types") or EVENT_TYPES)

    events, malformed = data.load_events()
    hits = [
        e for e in events
        if start <= _ts(e["ts"]) <= end
        and e["event_type"] in types
        and (not args.get("account") or e.get("account") == args["account"])
        and (not args.get("host") or e.get("host") == args["host"])
        and (not args.get("src_ip") or e.get("src_ip") == args["src_ip"])
    ]
    hits.sort(key=lambda e: e["ts"])
    shown = hits[:limit]
    return {
        "returned": len(shown),
        "total_matched": len(hits),
        "truncated": len(hits) > limit,
        "skipped_malformed_lines": malformed,
        "summary": {
            "by_event_type": dict(Counter(e["event_type"] for e in hits)),
            "by_src_ip": dict(Counter(e["src_ip"] for e in hits)),
            "by_account": dict(Counter(e["account"] for e in hits)),
            "first_ts": hits[0]["ts"] if hits else None,
            "last_ts": hits[-1]["ts"] if hits else None,
        },
        "events": [
            {k: e.get(k) for k in ("event_id", "ts", "event_type", "account", "host", "src_ip", "details", "ref")}
            for e in shown
        ],
        "note": "No matching events. Absence of events is a finding, not a failure." if not hits else None,
    }


SEARCH_LOGS = ToolSpec(
    name="search_logs",
    description=("Search the authentication and host event log (synthetic dataset). Filter by account, host and/or "
                 "source IP within a time window (max 31 days). Returns matching events with a `ref` you can cite as "
                 "evidence, plus counts by event type, IP and account."),
    parameters={
        "type": "object", "additionalProperties": False,
        "required": ["reason", "start", "end"],
        "properties": {
            "reason": REASON,
            "account": {"type": "string", "format": "email", "maxLength": 120},
            "host": {"type": "string", "pattern": "^[A-Z0-9-]{3,32}$"},
            "src_ip": {"type": "string", "format": "ipv4"},
            "event_types": {"type": "array", "items": {"enum": EVENT_TYPES}, "uniqueItems": True},
            "start": {"type": "string", "format": "date-time", "description": "ISO-8601 UTC, e.g. 2026-11-23T02:58:05Z"},
            "end": {"type": "string", "format": "date-time"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100},
        },
    },
    result_schema={
        "type": "object",
        "required": ["returned", "total_matched", "truncated", "skipped_malformed_lines", "summary", "events"],
        "properties": {
            "returned": {"type": "integer"}, "total_matched": {"type": "integer"},
            "events": {"type": "array", "items": {"type": "object", "required": ["event_id", "ts", "event_type", "ref"]}},
        },
    },
    func=_search_logs,
    source="synthetic log store (data/logs/events.jsonl)",
    mock=False,
)


# --------------------------------------------------------------------------- lookup_ip
def _ip_class(ip: ipaddress.IPv4Address) -> str:
    if any(ip in n for n in DOC_NETS):
        return "documentation range (RFC 5737), synthetic"
    if ip.is_private:
        return "private"
    if ip.is_loopback or ip.is_reserved or ip.is_multicast:
        return "special-purpose"
    return "public"


def _lookup_ip(args: dict) -> dict:
    ip = ipaddress.ip_address(args["ip"])
    intel = data.ip_intel()
    rec = intel.get(str(ip))
    out = {"ip": str(ip), "ip_class": _ip_class(ip), "found": rec is not None,
           "intel_source": intel.get("_meta", {}).get("source", "unknown")}
    if rec:
        out.update({k: rec.get(k) for k in ("verdict", "score", "tags", "asn", "country", "first_seen", "last_seen", "reports")})
    else:
        out["note"] = "IP not present in the intel source. Unknown is not the same as benign."
    return out


LOOKUP_IP = ToolSpec(
    name="lookup_ip",
    description=("Reputation and context for one IPv4 address from the MOCK intel file. Results are synthetic test "
                 "data and must be reported as mock, never as live threat intelligence."),
    parameters={
        "type": "object", "additionalProperties": False, "required": ["reason", "ip"],
        "properties": {"reason": REASON, "ip": {"type": "string", "format": "ipv4"}},
    },
    result_schema={
        "type": "object", "required": ["ip", "ip_class", "found", "intel_source"],
        "properties": {"found": {"type": "boolean"}, "score": {"type": ["integer", "null"], "minimum": 0, "maximum": 100}},
    },
    func=_lookup_ip,
    source="MOCK IP reputation (data/intel/ip_reputation_mock.json)",
    mock=True,
)


# --------------------------------------------------------------------------- search_cve
def _search_cve(args: dict) -> dict:
    if not args.get("query") and not args.get("id"):
        raise ToolInputError("give either query (keywords) or id (CVE-YYYY-NNNN or Txxxx)")
    snap = data.threat_intel()
    kind = args.get("kind")
    entries = [e for e in snap.get("entries", []) if not kind or e.get("kind") == kind]
    if args.get("id"):
        matches = [e for e in entries if e["id"].upper() == args["id"].upper()]
    else:
        words = [w for w in args["query"].lower().split() if len(w) > 2]
        scored = []
        for e in entries:
            hay = " ".join([e["id"], e["name"], e.get("summary", ""), " ".join(e.get("keywords", []))]).lower()
            score = sum(w in hay for w in words)
            if score:
                scored.append((score, e))
        matches = [e for _, e in sorted(scored, key=lambda x: -x[0])]
    matches = matches[: args.get("limit", 5)]
    return {
        "count": len(matches),
        "snapshot_date": snap.get("_meta", {}).get("snapshot_date"),
        "matches": [{k: e.get(k) for k in ("id", "kind", "name", "tactic", "cvss", "summary", "affects") if e.get(k) is not None}
                    for e in matches],
        "note": "No match in the local snapshot. This does not mean no relevant CVE or technique exists." if not matches else None,
    }


SEARCH_CVE = ToolSpec(
    name="search_cve",
    description=("Search a small MOCK offline snapshot of CVEs and MITRE ATT&CK techniques by keywords or exact id. "
                 "Use it to map observed behaviour to ATT&CK techniques or check known vulnerabilities of software."),
    parameters={
        "type": "object", "additionalProperties": False, "required": ["reason"],
        "properties": {
            "reason": REASON,
            "query": {"type": "string", "minLength": 3, "maxLength": 100},
            "id": {"type": "string", "pattern": "^(CVE-[0-9]{4}-[0-9]{4,}|T[0-9]{4}(\\.[0-9]{3})?)$"},
            "kind": {"enum": ["cve", "attack_technique"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
        },
    },
    result_schema={
        "type": "object", "required": ["count", "matches"],
        "properties": {"matches": {"type": "array", "items": {"type": "object", "required": ["id", "kind", "name"]}}},
    },
    func=_search_cve,
    source="MOCK local snapshot (data/intel/threat_intel_snapshot.json)",
    mock=True,
)


# --------------------------------------------------------------------------- get_asset_context
def _get_asset_context(args: dict) -> dict:
    if not args.get("host") and not args.get("account"):
        raise ToolInputError("give host and/or account")
    inv = data.assets()
    out = {"found": False}
    if args.get("host"):
        h = inv.get("hosts", {}).get(args["host"])
        out["host"] = {"name": args["host"], "found": h is not None, **(h or {})}
        out["found"] |= h is not None
    if args.get("account"):
        a = inv.get("accounts", {}).get(args["account"])
        out["account"] = {"name": args["account"], "found": a is not None, **(a or {})}
        out["found"] |= a is not None
    return out


GET_ASSET_CONTEXT = ToolSpec(
    name="get_asset_context",
    description=("Owner, department, criticality and security posture (e.g. MFA enrolment, usual IPs and hours) "
                 "for a host and/or account from the synthetic asset inventory."),
    parameters={
        "type": "object", "additionalProperties": False, "required": ["reason"],
        "properties": {
            "reason": REASON,
            "host": {"type": "string", "pattern": "^[A-Z0-9-]{3,32}$"},
            "account": {"type": "string", "format": "email", "maxLength": 120},
        },
    },
    result_schema={"type": "object", "required": ["found"], "properties": {"found": {"type": "boolean"}}},
    func=_get_asset_context,
    source="synthetic asset inventory (data/assets/inventory.json)",
    mock=False,
)

ALL_TOOLS = [SEARCH_LOGS, LOOKUP_IP, SEARCH_CVE, GET_ASSET_CONTEXT]
