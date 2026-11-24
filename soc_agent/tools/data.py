"""Read-only data access for the tools. No tool can write anywhere.

Live (default): the lab system we own (lab/state/events.jsonl written by the lab portal, lab/inventory.json),
real MITRE ATT&CK data (lab/intel/attack_techniques.json, extracted from MITRE's official STIX bundle),
and live public APIs: NVD for CVEs, AbuseIPDB (if ABUSEIPDB_API_KEY is set) or ipinfo.io for IP context.
Tests (SOC_DATA=fixtures): the frozen synthetic dataset in tests/fixtures/, no network.
"""
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from pathlib import Path

from ..paths import FIXTURES, LAB, LAB_STATE, ROOT, fixture_mode
from .base import DataUnavailable

HTTP_TIMEOUT = 6


def _tls() -> ssl.SSLContext:
    import certifi  # some Python builds do not see the OS certificate store
    return ssl.create_default_context(cafile=certifi.where())


def events_path() -> Path:
    return FIXTURES / "events.jsonl" if fixture_mode() else LAB_STATE / "events.jsonl"


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise DataUnavailable(f"{path.name} not found") from exc
    except json.JSONDecodeError as exc:
        raise DataUnavailable(f"{path.name} is corrupt: {exc}") from exc


def load_events() -> tuple[tuple[dict, ...], int]:
    """Returns (events, malformed_line_count). Re-read whenever the live log changes."""
    path = events_path()
    if not path.exists():
        raise DataUnavailable(f"{path.relative_to(ROOT)} not found (is the lab portal running?)")
    st = path.stat()
    return _parse_events(path, st.st_mtime_ns, st.st_size)


@lru_cache(maxsize=4)
def _parse_events(path: Path, _mtime: int, _size: int) -> tuple[tuple[dict, ...], int]:
    events, bad = [], 0
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
            if not all(k in e for k in ("ts", "event_type", "event_id")):
                raise ValueError("missing required keys")
        except ValueError:
            bad += 1
            continue
        e["ref"] = f"{path.relative_to(ROOT)}#L{n}"
        events.append(e)
    return tuple(events), bad


def assets() -> dict:
    return _read_json(FIXTURES / "inventory.json" if fixture_mode() else LAB / "inventory.json")


def assets_ref() -> str:
    return "tests/fixtures/inventory.json" if fixture_mode() else "lab/inventory.json"


def _get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "soc-agent-lab/1.0",
                                               **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_tls()) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        raise DataUnavailable(f"{urllib.parse.urlsplit(url).netloc} answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DataUnavailable(f"{urllib.parse.urlsplit(url).netloc} unreachable: {exc}") from exc


def ip_lookup(ip: str) -> tuple[dict | None, str]:
    """(record or None, source name). Record keys: verdict, score, tags, asn, country, reports."""
    if fixture_mode():
        intel = _read_json(FIXTURES / "ip_intel.json")
        return intel.get(ip), "test fixture (tests/fixtures/ip_intel.json)"
    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if key:
        d = _get_json("https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
                      {"Key": key}).get("data", {})
        score = d.get("abuseConfidenceScore")
        if not d.get("isPublic", True):
            return None, "AbuseIPDB (live)"
        verdict = "malicious" if (score or 0) >= 50 else "suspicious" if (score or 0) >= 10 else "no_known_abuse"
        return {"verdict": verdict, "score": score, "tags": [d.get("usageType")] if d.get("usageType") else [],
                "asn": d.get("isp"), "country": d.get("countryCode"), "reports": d.get("totalReports")}, "AbuseIPDB (live)"
    d = _get_json(f"https://ipinfo.io/{urllib.parse.quote(ip)}/json")
    if d.get("bogon"):
        return None, "ipinfo.io (live)"
    return {"verdict": "no_reputation_data", "score": None, "tags": [], "asn": d.get("org"), "country": d.get("country"),
            "reports": None}, "ipinfo.io (live, context only: no reputation score)"


def threat_intel() -> dict:
    """MITRE ATT&CK techniques (real, extracted) in live mode; the synthetic snapshot in tests."""
    return _read_json(FIXTURES / "threat_intel.json" if fixture_mode() else LAB / "intel" / "attack_techniques.json")


def nvd_search(query: str | None, cve_id: str | None, limit: int) -> list[dict]:
    """Live CVE search against NIST NVD (no key needed, rate-limited). Empty in fixture mode (snapshot covers CVEs)."""
    if fixture_mode():
        return []
    params = {"cveId": cve_id} if cve_id else {"keywordSearch": query, "resultsPerPage": limit}
    d = _get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params))
    out = []
    for v in d.get("vulnerabilities", [])[:limit]:
        c = v["cve"]
        desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
        metrics = c.get("metrics", {})
        cvss = next((m[0]["cvssData"]["baseScore"] for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
                     if (m := metrics.get(k))), None)
        out.append({"id": c["id"], "kind": "cve", "name": c["id"], "cvss": cvss, "summary": desc[:400]})
    return out
