# Hermes-Powered AI SOC Analyst (Cehpoint assessment)

A prototype junior SOC analyst: it receives a security alert, plans an investigation with approved
tools, and (by Day 5) produces an evidence-backed, auditable incident report with analyst approval
before any disruptive action. Hermes Agent is the orchestration layer; DeepSeek is the model.

> **Status: Day 2** - four validated, read-only tools wired into Hermes as the only enabled toolset; the agent
> picks tools from the plan, states why for every call, and returns cited evidence. Correlation and severity (Day 3),
> reporting and the approval gate (Day 4) and final testing (Day 5) follow.

## Prerequisites

- Python 3.11
- [uv](https://docs.astral.sh/uv/) (or plain `pip`)
- A DeepSeek API key

## Setup

```bash
git clone <repo-url> cehpoint-soc && cd cehpoint-soc
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -r requirements.txt
cp .env.example .env          # then put your DEEPSEEK_API_KEY in .env (never commit it)
```

Hermes Agent is installed from PyPI (`hermes-agent==0.16.0`) into the project venv. It runs with its own
home directory `.hermes_home/` inside the repo, so it does not read or change any personal Hermes setup.

## Run

```bash
# Validate the alert and produce a structured investigation plan through Hermes + DeepSeek
.venv/bin/python -m soc_agent plan data/alerts/ALR-2026-0001.json

# See exactly what is sent to the model, without calling it
.venv/bin/python -m soc_agent plan data/alerts/ALR-2026-0001.json --show-prompt
```

```bash
# Day 2: plan, then let Hermes gather evidence with the four approved tools
.venv/bin/python -m soc_agent investigate data/alerts/ALR-2026-0001.json

# List the approved tools (add --schemas for the JSON schemas Hermes receives)
.venv/bin/python -m soc_agent tools --schemas

# Call one tool directly, without the model (shows validation and error handling)
.venv/bin/python -m soc_agent call lookup_ip '{"reason": "Check the source IP reputation", "ip": "203.0.113.45"}'
.venv/bin/python -m soc_agent call search_logs '{"reason": "Dump all logs", "start": "2026-11-01T00:00:00Z", "end": "2026-11-23T00:00:00Z"}'

# Simulate a tool failure (timeout | malformed | unavailable | crash)
SOC_FAULTS="lookup_ip=timeout" .venv/bin/python -m soc_agent investigate data/alerts/ALR-2026-0001.json
```

Each run writes to `runs/<run-id>/`: `plan.json`, `tool_trace.json` (every tool call with its reason, arguments,
outcome and duration), `evidence.json` (cited findings) and `audit.jsonl` (everything, timestamped).
A sample trace and evidence report from a real run are in `docs/samples/`.

## Tools (Day 2)

| Tool | What it returns | Source | Guard rails |
|---|---|---|---|
| `search_logs` | Matching auth/host events with a citable `ref` (file#line), counts by type/IP/account | synthetic log store | needs account, host or IP; window max 31 days; limit max 200; skips and counts malformed lines |
| `lookup_ip` | Verdict, score, tags, ASN, first/last seen | **MOCK** intel file | IPv4 only; unknown IP is reported as unknown, not benign |
| `search_cve` | CVE and MITRE ATT&CK entries by keyword or id | **MOCK** local snapshot | id pattern enforced; empty result says so |
| `get_asset_context` | Host owner, criticality, software; account MFA, usual IPs and hours | synthetic inventory | host or account required |

All four are read-only. Each call goes through one wrapper that validates arguments against the tool's JSON
schema, requires a `reason`, enforces a 5 s timeout, validates the result shape, and returns
`{tool, ok, source, mock, result, error}` with error codes `invalid_input`, `timeout`, `malformed_output`,
`data_unavailable`, `internal_error` or `not_permitted`. Hermes is built with `enabled_toolsets=["soc"]`, so these
four are the only tools the model can see; its built-in terminal, file, browser and web tools are never enabled.

Regenerate the synthetic data (deterministic, same seed gives identical files):

```bash
.venv/bin/python data/generate_synthetic.py
```

## Tests

```bash
.venv/bin/python -m pytest -q
```

Tests run offline with a scripted model: no API key or network needed.

## Layout

```
schemas/alert.schema.json              input contract (what the SIEM hands over)
schemas/investigation_plan.schema.json output contract (what the agent must return)
data/alerts/ALR-2026-0001.json         mandatory scenario: 50 failed logins then success from new IP (synthetic)
data/logs/events.jsonl                 30 days of synthetic auth/host events (+1 deliberately malformed line)
data/intel/*.json                      MOCK IP reputation and MOCK CVE/ATT&CK snapshot
data/assets/inventory.json             synthetic hosts and accounts
data/generate_synthetic.py             seeded generator for the files above
soc_agent/tools/                       the four tools, shared wrapper, Hermes registration
soc_agent/investigate.py               evidence-gathering stage (tool-enabled Hermes agent)
docs/samples/                          trace and evidence from a real run
soc_agent/hermes_runtime.py            builds the Hermes agent (DeepSeek, isolated home, toolsets)
soc_agent/planner.py                   prompt, plan parsing + checks, one repair retry
soc_agent/validation.py                JSON Schema validation
soc_agent/audit.py                     append-only JSONL audit trail
soc_agent/__main__.py                  CLI
docs/ARCHITECTURE.md                   architecture diagram and design notes
```

## Data provenance

All data in this repo is **synthetic**, as permitted by the brief (section 8, "Authorized data only").
IPs come from the RFC 5737 documentation ranges, domains are RFC 2606 `example.com`, and users/hosts are
invented. No real system, user or log is used. Mock intelligence sources are labelled as mock wherever
they appear.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DEEPSEEK_API_KEY` | none (required) | DeepSeek API key, read from `.env` |
| `SOC_MODEL` | `deepseek-chat` | DeepSeek model id used by Hermes |
| `SOC_FAULTS` | empty | Fault injection for demos/tests, e.g. `lookup_ip=timeout,search_logs=malformed` |
