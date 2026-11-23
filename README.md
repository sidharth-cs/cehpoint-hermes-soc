# Hermes-Powered AI SOC Analyst (Cehpoint assessment)

A prototype junior SOC analyst: it receives a security alert, plans an investigation with approved
tools, and (by Day 5) produces an evidence-backed, auditable incident report with analyst approval
before any disruptive action. Hermes Agent is the orchestration layer; DeepSeek is the model.

> **Status: Day 1** - alert intake + validation, Hermes agent entry point, structured investigation plan, audit trail.
> Tools (Day 2), correlation (Day 3), reporting and approval gate (Day 4) and full tests (Day 5) follow.

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

## Run (Day 1)

```bash
# Validate the alert and produce a structured investigation plan through Hermes + DeepSeek
.venv/bin/python -m soc_agent plan data/alerts/ALR-2026-0001.json

# See exactly what is sent to the model, without calling it
.venv/bin/python -m soc_agent plan data/alerts/ALR-2026-0001.json --show-prompt
```

Each run writes `runs/<run-id>/plan.json` and `runs/<run-id>/audit.jsonl`
(alert received, full prompt, raw model output, validation result, timestamps).

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
