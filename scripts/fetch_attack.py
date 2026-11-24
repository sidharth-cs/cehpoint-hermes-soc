"""Download MITRE ATT&CK (Enterprise) from MITRE's official CTI repository and keep a compact technique list.

    .venv/bin/python scripts/fetch_attack.py

Writes lab/intel/attack_techniques.json (real data, not mock). Re-run to update.
"""
import json
import re
import ssl
import sys
import urllib.request
from datetime import date
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parent.parent / "lab" / "intel" / "attack_techniques.json"


def main() -> int:
    import certifi  # Homebrew/python.org Python may not see the system CA store
    ctx = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(URL, timeout=120, context=ctx) as r:
        bundle = json.load(r)
    version, entries = "latest (master branch)", []
    for o in bundle["objects"]:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version")
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        desc = re.sub(r"\(Citation:[^)]*\)", "", o.get("description", "")).strip()
        entries.append({"id": ext["external_id"], "kind": "attack_technique", "name": o["name"],
                        "tactic": ", ".join(p["phase_name"] for p in o.get("kill_chain_phases", [])),
                        "summary": desc[:400], "url": ext.get("url")})
    entries.sort(key=lambda e: e["id"])
    OUT.write_text(json.dumps({"_meta": {"source": URL, "attack_version": version, "fetched": date.today().isoformat(),
                                         "note": "Official MITRE ATT&CK Enterprise techniques (not mock)."},
                               "entries": entries}, indent=1) + "\n")
    print(f"{len(entries)} techniques (ATT&CK v{version}) -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
