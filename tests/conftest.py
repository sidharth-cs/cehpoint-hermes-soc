import copy
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "alerts" / "ALR-2026-0001.json"


@pytest.fixture
def alert():
    return json.loads(SAMPLE.read_text())


@pytest.fixture
def good_plan():
    return {
        "alert_id": "ALR-2026-0001",
        "summary": "Possible credential-stuffing compromise of j.doe@example.com from 203.0.113.45.",
        "hypotheses": [
            {"id": "H1", "description": "Brute force succeeded; account compromised."},
            {"id": "H2", "description": "Legitimate user mistyped password, then logged in from a new network."},
        ],
        "steps": [
            {"step": 1, "objective": "Pull auth events for the account in the window", "tool": "search_logs",
             "arguments": {"account": "j.doe@example.com", "start": "2026-11-23T02:58:05Z", "end": "2026-11-23T03:13:51Z"},
             "rationale": "Confirms counts and order", "evidence_sought": "failed/success events", "tests_hypotheses": ["H1", "H2"]},
            {"step": 2, "objective": "Check source IP", "tool": "lookup_ip", "arguments": {"ip": "203.0.113.45"},
             "rationale": "Known-bad IP raises likelihood of H1", "evidence_sought": "reputation", "tests_hypotheses": ["H1"]},
            {"step": 3, "objective": "Correlate findings", "tool": "none", "arguments": {},
             "rationale": "Combine evidence", "evidence_sought": "timeline", "tests_hypotheses": ["H1", "H2"]},
        ],
        "questions": ["Which account and asset are involved?"],
        "safety_notes": ["Blocking 203.0.113.45 requires analyst approval."],
    }


@pytest.fixture
def audit(tmp_path):
    from soc_agent.audit import AuditLog
    return AuditLog("ALR-2026-0001", runs_dir=tmp_path)


def clone(d):
    return copy.deepcopy(d)
