import json

import pytest

from soc_agent.tools import BY_NAME, run_tool, start_trace, stop_trace
from soc_agent.tools import data as tool_data

R = "Testing this tool for the investigation."
WINDOW = {"start": "2026-11-23T02:58:05Z", "end": "2026-11-23T03:13:51Z"}


# ---------- search_logs
def test_search_logs_finds_the_alert_pattern():
    r = run_tool("search_logs", {"reason": R, "account": "j.doe@example.com", **WINDOW})
    assert r["ok"] and not r["mock"]
    res = r["result"]
    assert res["summary"]["by_event_type"] == {"auth_failure": 50, "auth_success": 1}
    assert res["summary"]["by_src_ip"] == {"203.0.113.45": 51}
    assert all(e["ref"].startswith("tests/fixtures/events.jsonl#L") for e in res["events"])


def test_search_logs_reports_and_skips_malformed_lines():
    r = run_tool("search_logs", {"reason": R, "src_ip": "203.0.113.45", **WINDOW})
    assert r["result"]["skipped_malformed_lines"] == 1


def test_search_logs_empty_result_is_ok_with_note():
    r = run_tool("search_logs", {"reason": R, "account": "nobody@example.com", **WINDOW})
    assert r["ok"] and r["result"]["total_matched"] == 0
    assert "Absence" in r["result"]["note"]


def test_search_logs_truncates_to_limit():
    r = run_tool("search_logs", {"reason": R, "src_ip": "203.0.113.45", "limit": 5, **WINDOW})
    assert r["result"]["returned"] == 5 and r["result"]["truncated"] is True


@pytest.mark.parametrize("args, code_or_text", [
    ({**WINDOW}, "at least one of"),                                                    # unbounded dump
    ({"account": "j.doe@example.com", "start": WINDOW["end"], "end": WINDOW["start"]}, "not be before start"),
    ({"account": "j.doe@example.com", "start": "2026-09-01T00:00:00Z", "end": "2026-11-23T00:00:00Z"}, "31 days"),
    ({"src_ip": "300.1.1.1", **WINDOW}, "ipv4"),
    ({"account": "j.doe@example.com", "start": "yesterday", "end": WINDOW["end"]}, "ISO-8601"),
    ({"account": "j.doe@example.com", "start": "2026-11-23T02:58:05", "end": WINDOW["end"]}, "timezone"),
    ({"account": "j.doe@example.com", "drop_table": True, **WINDOW}, "Additional properties"),
])
def test_search_logs_rejects_bad_input(args, code_or_text):
    r = run_tool("search_logs", {"reason": R, **args})
    assert not r["ok"] and r["error"]["code"] == "invalid_input"
    assert code_or_text in r["error"]["message"]


def test_reason_is_required():
    r = run_tool("lookup_ip", {"ip": "203.0.113.45"})
    assert r["error"]["code"] == "invalid_input" and "reason" in r["error"]["message"]


# ---------- lookup_ip
def test_lookup_ip_known_bad_is_labelled_mock():
    r = run_tool("lookup_ip", {"reason": R, "ip": "203.0.113.45"})
    assert r["ok"] and r["mock"] is True and r["result"]["intel_source"].startswith("test fixture")
    assert r["result"]["verdict"] == "malicious"
    assert "documentation range" in r["result"]["ip_class"]


def test_lookup_ip_unknown_is_not_called_benign():
    r = run_tool("lookup_ip", {"reason": R, "ip": "203.0.113.200"})
    assert r["ok"] and r["result"]["found"] is False and "not the same as benign" in r["result"]["note"]


# ---------- search_cve
def test_search_cve_keyword_maps_to_attack():
    r = run_tool("search_cve", {"reason": R, "query": "password spray many accounts", "kind": "attack_technique"})
    assert r["ok"] and r["mock"] and r["result"]["matches"][0]["id"] == "T1110.003"


def test_search_cve_exact_id_and_miss():
    assert run_tool("search_cve", {"reason": R, "id": "CVE-2023-23397"})["result"]["count"] == 1
    miss = run_tool("search_cve", {"reason": R, "id": "CVE-1999-0001"})
    assert miss["ok"] and miss["result"]["count"] == 0 and miss["result"]["note"]


def test_search_cve_needs_query_or_id():
    assert run_tool("search_cve", {"reason": R})["error"]["code"] == "invalid_input"


# ---------- get_asset_context
def test_asset_context_host_and_account():
    r = run_tool("get_asset_context", {"reason": R, "host": "WS-FIN-014", "account": "j.doe@example.com"})
    assert r["result"]["host"]["criticality"] == "high"
    assert r["result"]["account"]["mfa_enrolled"] is False


def test_asset_context_unknown_host():
    r = run_tool("get_asset_context", {"reason": R, "host": "WS-NOPE-001"})
    assert r["ok"] and r["result"]["found"] is False


# ---------- permissions and failures
def test_unapproved_tool_is_refused():
    r = run_tool("block_ip", {"reason": R, "ip": "203.0.113.45"})
    assert not r["ok"] and r["error"]["code"] == "not_permitted"


def test_timeout_is_reported(monkeypatch):
    monkeypatch.setenv("SOC_FAULTS", "lookup_ip=timeout")
    monkeypatch.setattr(BY_NAME["lookup_ip"], "timeout_s", 0.2)
    r = run_tool("lookup_ip", {"reason": R, "ip": "203.0.113.45"})
    assert not r["ok"] and r["error"]["code"] == "timeout"


def test_malformed_output_is_discarded(monkeypatch):
    monkeypatch.setenv("SOC_FAULTS", "search_logs=malformed")
    r = run_tool("search_logs", {"reason": R, "account": "j.doe@example.com", **WINDOW})
    assert not r["ok"] and r["error"]["code"] == "malformed_output" and r["result"] is None


def test_crash_does_not_leak_traceback(monkeypatch):
    monkeypatch.setenv("SOC_FAULTS", "search_cve=crash")
    r = run_tool("search_cve", {"reason": R, "query": "brute force"})
    assert r["error"]["code"] == "internal_error" and "Traceback" not in r["error"]["message"]


def test_missing_dataset_is_data_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(tool_data, "FIXTURES", tmp_path)  # no ip_intel.json there
    r = run_tool("lookup_ip", {"reason": R, "ip": "203.0.113.45"})
    assert r["error"]["code"] == "data_unavailable"


def test_corrupt_dataset_is_data_unavailable(monkeypatch, tmp_path):
    (tmp_path / "inventory.json").write_text("{oops")
    monkeypatch.setattr(tool_data, "FIXTURES", tmp_path)
    r = run_tool("get_asset_context", {"reason": R, "host": "WS-FIN-014"})
    assert r["error"]["code"] == "data_unavailable"


def test_trace_records_reason_args_and_outcome():
    trace = start_trace()
    try:
        run_tool("lookup_ip", {"reason": "Check reputation of the source IP.", "ip": "203.0.113.45"})
        run_tool("search_cve", {"reason": R})
    finally:
        stop_trace()
    assert [c["tool"] for c in trace.calls] == ["lookup_ip", "search_cve"]
    assert trace.calls[0]["reason"] == "Check reputation of the source IP."
    assert trace.calls[0]["arguments"] == {"ip": "203.0.113.45"} and trace.calls[0]["mock"] is True
    assert trace.calls[1]["ok"] is False and trace.calls[1]["error"]["code"] == "invalid_input"


def test_every_tool_schema_is_hermes_compatible():
    for spec in BY_NAME.values():
        s = spec.hermes_schema()
        assert s["name"] == spec.name and s["parameters"]["type"] == "object"
        assert "reason" in s["parameters"]["required"]
        assert s["parameters"]["additionalProperties"] is False
        json.dumps(s)
