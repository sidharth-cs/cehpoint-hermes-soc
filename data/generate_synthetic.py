"""Generate the synthetic datasets used by the tools. Deterministic: same seed -> identical files.

    python data/generate_synthetic.py

Everything here is invented. IPs come from RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), domains are RFC 2606 example.com, users and hosts are made up.
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20261123
OUT = Path(__file__).resolve().parent
T0 = datetime(2026, 11, 23, 3, 13, 51, tzinfo=timezone.utc)  # the successful suspicious login

OFFICE_IP = "198.51.100.10"
VPN_IP = "198.51.100.22"
ATTACKER_IP = "203.0.113.45"
USERS = {
    "j.doe@example.com": "WS-FIN-014",
    "a.kumar@example.com": "WS-FIN-009",
    "m.lee@example.com": "WS-HR-003",
    "s.rao@example.com": "WS-ENG-021",
}


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    rng = random.Random(SEED)
    events = []

    def add(ts, event_type, account, host, src_ip, **details):
        events.append({"ts": iso(ts), "event_type": event_type, "account": account, "host": host,
                       "src_ip": src_ip, "details": details, "data_provenance": "synthetic"})

    # 30 days of normal working-hours logins (03:30-12:30 UTC = 09:00-18:00 IST) from office/VPN.
    for day in range(30, 0, -1):
        date = (T0 - timedelta(days=day)).replace(hour=0, minute=0, second=0)
        if date.weekday() >= 5:
            continue
        for account, host in USERS.items():
            ts = date + timedelta(hours=3, minutes=30 + rng.randint(0, 50), seconds=rng.randint(0, 59))
            ip = OFFICE_IP if rng.random() < 0.8 else VPN_IP
            if rng.random() < 0.15:  # ordinary typo before success
                add(ts - timedelta(seconds=20), "auth_failure", account, host, ip, reason="bad_password")
            add(ts, "auth_success", account, host, ip, method="password", mfa="not_enrolled" if account == "j.doe@example.com" else "passed")
            add(ts + timedelta(hours=8, minutes=rng.randint(0, 59)), "logout", account, host, ip)

    # The attack: 50 failures from the attacker IP over ~15 minutes, then success.
    start = datetime(2026, 11, 23, 2, 58, 5, tzinfo=timezone.utc)
    step = (T0 - timedelta(seconds=14) - start) / 49
    for i in range(50):
        add(start + step * i, "auth_failure", "j.doe@example.com", "WS-FIN-014", ATTACKER_IP,
            reason="bad_password", user_agent="python-requests/2.31")
    add(T0, "auth_success", "j.doe@example.com", "WS-FIN-014", ATTACKER_IP,
        method="password", mfa="not_enrolled", user_agent="python-requests/2.31")

    # Same IP sprays two other accounts in the same window (campaign signal). Both fail.
    for account, n in (("a.kumar@example.com", 12), ("m.lee@example.com", 8)):
        for i in range(n):
            add(start + timedelta(minutes=1, seconds=70 * i + rng.randint(0, 9)), "auth_failure",
                account, USERS[account], ATTACKER_IP, reason="bad_password", user_agent="python-requests/2.31")

    # Post-login activity in the attacker session.
    add(T0 + timedelta(minutes=3, seconds=12), "mailbox_rule_created", "j.doe@example.com", "WS-FIN-014",
        ATTACKER_IP, rule_name="..", action="forward_all", forward_to="ext.billing-update@example.org")
    add(T0 + timedelta(minutes=7, seconds=40), "file_access", "j.doe@example.com", "WS-FIN-014", ATTACKER_IP,
        share=r"\\fs-fin-01\payables", files_read=14, bytes_read=8_421_377)
    add(T0 + timedelta(minutes=11, seconds=2), "logout", "j.doe@example.com", "WS-FIN-014", ATTACKER_IP)

    # Real user starts work later that morning from the office, unaware.
    add(T0 + timedelta(hours=1, minutes=4), "auth_success", "j.doe@example.com", "WS-FIN-014", OFFICE_IP,
        method="password", mfa="not_enrolled")

    events.sort(key=lambda e: (e["ts"], e["account"], e["event_type"]))
    for n, e in enumerate(events, 1):
        e["event_id"] = f"EVT-{n:05d}"

    lines = [json.dumps(e, sort_keys=True) for e in events]
    # One deliberately corrupted line (truncated write) so the tools must handle malformed data.
    lines.insert(len(lines) // 3, '{"ts": "2026-11-12T04:01:07Z", "event_type": "auth_succ')
    (OUT / "logs" / "events.jsonl").write_text("\n".join(lines) + "\n")

    intel = {
        "_meta": {"source": "MOCK", "note": "Synthetic IP reputation for testing. Not live threat intelligence."},
        ATTACKER_IP: {"verdict": "malicious", "score": 87, "tags": ["credential-stuffing", "password-spray"],
                      "asn": "AS64500 (documentation ASN)", "country": "ZZ", "first_seen": "2026-10-02",
                      "last_seen": "2026-11-23", "reports": 23},
        OFFICE_IP: {"verdict": "benign", "score": 2, "tags": ["corporate-egress"], "asn": "AS64501 (documentation ASN)",
                    "country": "IN", "first_seen": "2024-01-15", "last_seen": "2026-11-23", "reports": 0},
        VPN_IP: {"verdict": "benign", "score": 4, "tags": ["corporate-vpn"], "asn": "AS64501 (documentation ASN)",
                 "country": "IN", "first_seen": "2024-01-15", "last_seen": "2026-11-23", "reports": 0},
        "192.0.2.77": {"verdict": "suspicious", "score": 55, "tags": ["scanner"], "asn": "AS64502 (documentation ASN)",
                       "country": "ZZ", "first_seen": "2026-09-01", "last_seen": "2026-11-20", "reports": 4},
    }
    (OUT / "intel" / "ip_reputation_mock.json").write_text(json.dumps(intel, indent=2, sort_keys=True) + "\n")

    assets = {
        "_meta": {"source": "synthetic-cmdb", "note": "Synthetic asset inventory."},
        "hosts": {
            "WS-FIN-014": {"owner": "j.doe@example.com", "department": "Finance", "role": "Accounts payable workstation",
                           "criticality": "high", "os": "Windows 11 23H2", "software": ["Microsoft Outlook 2021", "Citrix Workspace 2309"]},
            "WS-FIN-009": {"owner": "a.kumar@example.com", "department": "Finance", "role": "Treasury workstation",
                           "criticality": "high", "os": "Windows 11 23H2", "software": ["Microsoft Outlook 2021"]},
            "WS-HR-003": {"owner": "m.lee@example.com", "department": "HR", "role": "HR workstation",
                          "criticality": "medium", "os": "Windows 11 23H2", "software": ["Microsoft Outlook 2021"]},
            "WS-ENG-021": {"owner": "s.rao@example.com", "department": "Engineering", "role": "Developer workstation",
                           "criticality": "medium", "os": "Ubuntu 24.04", "software": ["Docker 27"]},
        },
        "accounts": {
            "j.doe@example.com": {"display_name": "J. Doe", "department": "Finance", "title": "AP Analyst",
                                  "privileged": False, "mfa_enrolled": False, "manager": "r.iyer@example.com",
                                  "usual_ips": [OFFICE_IP, VPN_IP], "usual_hours_utc": "03:30-12:30"},
            "a.kumar@example.com": {"display_name": "A. Kumar", "department": "Finance", "title": "Treasury Analyst",
                                    "privileged": False, "mfa_enrolled": True, "manager": "r.iyer@example.com",
                                    "usual_ips": [OFFICE_IP, VPN_IP], "usual_hours_utc": "03:30-12:30"},
            "m.lee@example.com": {"display_name": "M. Lee", "department": "HR", "title": "HR Generalist",
                                  "privileged": False, "mfa_enrolled": True, "manager": "p.nair@example.com",
                                  "usual_ips": [OFFICE_IP], "usual_hours_utc": "03:30-12:30"},
            "s.rao@example.com": {"display_name": "S. Rao", "department": "Engineering", "title": "Engineer",
                                  "privileged": True, "mfa_enrolled": True, "manager": "k.menon@example.com",
                                  "usual_ips": [OFFICE_IP, VPN_IP], "usual_hours_utc": "03:30-12:30"},
        },
    }
    (OUT / "assets" / "inventory.json").write_text(json.dumps(assets, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(events)} events (+1 malformed line), {len(intel) - 1} IP records, {len(assets['hosts'])} hosts")


if __name__ == "__main__":
    main()
