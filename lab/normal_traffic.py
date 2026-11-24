"""Normal user activity on the lab portal, so the log has a baseline before the attack.

    .venv/bin/python -m lab.normal_traffic

Each user logs in from a usual office/VPN IP with the right password (and one-time code where MFA is on),
does nothing unusual, and logs out. S. Rao mistypes the password once first, a benign failure.
"""
import json
import sys
import time
from pathlib import Path

import httpx

from lab.attack import TARGET

CREDS = {k: v for k, v in json.loads((Path(__file__).resolve().parent / "test_credentials.json").read_text()).items()
         if not k.startswith("_")}
OFFICE = {"j.doe@lab.example": "198.51.100.10", "a.kumar@lab.example": "198.51.100.22",
          "m.lee@lab.example": "198.51.100.10", "s.rao@lab.example": "198.51.100.10"}
BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"


def main() -> int:
    for user, ip in OFFICE.items():
        with httpx.Client(base_url=TARGET, headers={"X-Forwarded-For": ip, "User-Agent": BROWSER}, timeout=5) as c:
            if user.startswith("s.rao"):
                c.post("/login", json={"username": user, "password": CREDS[user]["password"][:-1]})
            r = c.post("/login", json={"username": user, **CREDS[user]})
            if r.status_code != 200:
                print(f"{user}: login failed HTTP {r.status_code}")
                return 1
            h = {"Authorization": f"Bearer {r.json()['token']}"}
            if "Finance" in user or user.startswith("j.doe"):
                c.get("/files/payables", headers=h)
            c.post("/logout", headers=h)
            print(f"{user}: normal login and logout from {ip}")
        time.sleep(0.2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
