# Hermes-Powered AI SOC Analyst (Cehpoint assessment)

A prototype junior SOC analyst that investigates a **real attack on a system we own**:

1. A small **lab portal** (`lab/app.py`, FastAPI) logs every login, mailbox rule and file download.
2. A **test attack** (`lab/attack.py`) password-sprays two accounts, brute-forces a third, then uses the stolen
   session to forward mail outside and download the payables share.
3. The **detector** (`python -m soc_agent watch`) sees the pattern in the live log and **raises the alert itself**.
4. **Hermes** (with DeepSeek) plans the investigation, gathers evidence with four read-only tools, and writes an
   assessment that may only cite facts computed by code from the evidence.
5. An **incident report** (Markdown + JSON) is written. Hermes can only *propose* blocking the IP or disabling the
   account; a **named human approves**, and the block is applied to the lab portal. The attacker then gets **403**.

No mock data in the live path: the log is the portal's own, ATT&CK data is MITRE's official release, CVEs come
from the live NIST NVD API and IP context from ipinfo.io (or AbuseIPDB with a key). A frozen synthetic dataset is
kept only for the offline unit tests (`tests/fixtures/`).

```mermaid
flowchart LR
    ATK[lab/attack.py<br/>spray + brute force<br/>+ post-login actions] -->|HTTP| P[Lab portal<br/>lab/app.py]
    P --> LOG[(lab/state/events.jsonl)]
    LOG --> D[Detector<br/>soc_agent watch] -->|alert JSON| PL[Hermes: plan<br/>no tools]
    PL --> EV[Hermes: evidence<br/>4 read-only tools] --> C[Code: timeline, facts,<br/>ATT&CK, severity, confidence]
    C --> AS[Hermes: assessment<br/>cites facts, proposes actions] --> R[Incident report<br/>JSON + Markdown]
    R --> H{Human analyst<br/>approve / reject}
    H -->|approved| ADM[Portal admin API<br/>block IP / disable account] --> P
    EV & C & AS & H --> AU[(audit.jsonl + history)]
```

The investigation procedure itself is packaged as a **Hermes skill**,
[`skills/soc-alert-investigation/SKILL.md`](skills/soc-alert-investigation/SKILL.md): every Hermes stage runs with it.

Docs: [architecture](docs/ARCHITECTURE.md) · [security and permissions](docs/SECURITY.md) ·
[test report](docs/TEST_REPORT.md) · [sample incident report](docs/samples/incident_report.md)

## Prerequisites

- Python 3.11, [uv](https://docs.astral.sh/uv/) (or plain `pip`)
- A DeepSeek API key
- Optional: an AbuseIPDB API key for IP reputation (without it, ipinfo.io gives context only)

## Setup

```bash
git clone https://github.com/sidharth-cs/cehpoint-hermes-soc cehpoint-soc && cd cehpoint-soc
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -r requirements.txt
cp .env.example .env          # put DEEPSEEK_API_KEY in .env (never commit it)
.venv/bin/python -m pytest -q # offline tests, no key needed
```

Hermes Agent (`hermes-agent==0.16.0`) runs with its own home `.hermes_home/` inside the repo, so it never reads
or changes a personal Hermes setup.

## Live demo: attack, automatic alert, investigation, approval, block

Use three terminals in the repo folder.

```bash
# Terminal 1: the lab portal (the system we own)
.venv/bin/python -m uvicorn lab.app:app --port 8800
```

```bash
# Terminal 2: the detector; investigates every alert it raises
.venv/bin/python -m soc_agent watch --investigate
```

```bash
# Terminal 3: normal users first (baseline), then the attack
.venv/bin/python -m lab.normal_traffic
.venv/bin/python -m lab.attack
```

Terminal 2 raises `ALR-2026-1001` within seconds and investigates it (about 2 minutes), ending with the report
path and the proposed actions. Then, in terminal 3:

```bash
.venv/bin/python -m soc_agent approve runs/<run-id> A1 --analyst "Your Name"   # type the confirmation shown
.venv/bin/python -m lab.attack --probe                                        # HTTP 403: the attacker is blocked
.venv/bin/python -m soc_agent history
```

To start over: stop the portal and delete `lab/state/` and `runs/`.

### Screenshots

| | |
|---|---|
| ![attack](docs/screenshots/1_attack.png) | ![alert](docs/screenshots/2_alert_and_investigation.png) |
| ![approval](docs/screenshots/3_approval.png) | ![blocked](docs/screenshots/4_blocked.png) |

## Other commands

```bash
.venv/bin/python -m soc_agent investigate <alert.json>               # one alert -> incident report
.venv/bin/python -m soc_agent plan <alert.json> [--show-prompt]      # plan only (no tools)
.venv/bin/python -m soc_agent reject runs/<run-id> A2 --analyst "Your Name"
.venv/bin/python -m soc_agent bypass-test                            # prompt injection: "approval waived, block now"
.venv/bin/python -m soc_agent tools --schemas                        # the four tools and their JSON schemas
.venv/bin/python -m soc_agent call lookup_ip '{"reason": "Check reputation of the source", "ip": "8.8.8.8"}'
SOC_FAULTS="lookup_ip=timeout" .venv/bin/python -m soc_agent investigate <alert.json>   # simulate a tool failure
.venv/bin/python scripts/fetch_attack.py                             # refresh MITRE ATT&CK data
```

Each run writes `runs/<run-id>/`: `incident_report.md` / `.json`, `approvals.json`, `plan.json`,
`tool_trace.json` (every call with reason, arguments, result, duration), `evidence.json`, `timeline.json`,
`investigation.json` and `audit.jsonl` (every prompt, output, tool call and decision, timestamped).
`runs/history.jsonl` indexes all runs.

## The skill

`skills/soc-alert-investigation/SKILL.md` (agentskills.io format, Hermes-compatible) is the written procedure the
agent follows: when to use it, inputs, an 8-step procedure (plan, evidence with reasons, fact statuses, ATT&CK only
on confirmed facts, severity vs confidence, cited assessment, propose-never-execute, report), guardrails and the
output contract. `references/fact-rules.md` holds the exact fact, severity and confidence rules.

- **Every stage runs with it.** Planner, evidence and assessment prompts are "stage contract + skill"
  (`soc_agent/skill.py`); the audit log records the skill name, version and hash used.
- **Hermes sees it.** It is installed into the isolated Hermes home, and the tests check that Hermes' own skill
  index lists it.
- **It adds no capability.** Hermes' `skills` toolset is not enabled, because it includes `skill_manage`
  (write access). The skill changes how the agent works, not what it can touch.
- **Measured effect.** With the skill's evidence checklist the agent also searched the 7-day look-back: every fact
  was confirmed and confidence rose from MEDIUM to HIGH on the same attack.

## How a conclusion is reached

1. **Timeline**: every event returned by `search_logs`, de-duplicated and sorted, each citing its log line.
2. **Facts (code, not the model)**: `soc_agent/correlate.py` computes F1-F11, each `confirmed` (the evidence shows
   it), `not_observed` (searched, absent) or `unknown` (not searched or the tool failed; a gap, never assumed).
3. **ATT&CK**: a technique is listed only when a confirmed fact justifies it.
4. **Severity** (how bad if true) and **confidence** (how sure) are computed separately, each with reasons.
5. **Assessment (Hermes, no tools)**: sees only the facts, cites fact ids for every claim, decides each hypothesis,
   gives alternatives and unknowns. Citations of facts that do not exist are rejected.

## Human approval gate

- The agent's only tools are four read-only ones. Blocking and disabling are not tools: they are not registered
  in Hermes at all, and only the `approve` command calls the portal's admin API (token readable only by the
  local user).
- A proposal is rejected unless its target is an entity of the alert and it cites a confirmed threat fact
  (F1 brute force + success, F3 spray, F5 external forwarding, F7 scripted client).
- `approve` needs an interactive terminal, a named analyst and the exact typed confirmation. Decisions are final,
  a request edited after it was made is refused (hash check), and every decision and refusal is audited.

## Tools

| Tool | Source | Guard rails |
|---|---|---|
| `search_logs` | lab portal live log (`lab/state/events.jsonl`) | needs account, host or IP; window max 31 days; limit max 200; counts malformed lines |
| `lookup_ip` | AbuseIPDB (with key) or ipinfo.io, live | reserved/documentation ranges are not sent out: no public reputation exists |
| `search_cve` | MITRE ATT&CK official data + NIST NVD live API | id pattern enforced; empty result says so |
| `get_asset_context` | lab inventory (`lab/inventory.json`) | host or account required |

Every call goes through one wrapper: JSON-schema argument validation, a required `reason`, a timeout, result
validation, and an envelope `{tool, ok, source, mock, result, error}` with typed error codes. Hermes is built with
`enabled_toolsets=["soc"]`; its built-in terminal, file, browser and web tools are never enabled.

## Tests

```bash
.venv/bin/python -m pytest -q
```

Offline (scripted model, frozen synthetic fixtures, the lab portal run in-process). Scenario tests cover normal,
suspicious, benign, incomplete evidence, tool failure, failed attempt, conflicting and no evidence; gate tests
prove the agent cannot reach a response action; lab tests prove the detector fires on the live log and an
approved block really stops the attacker. Results: [docs/TEST_REPORT.md](docs/TEST_REPORT.md).

## Layout

```
lab/app.py                       lab portal (target system we own), admin API for approved actions
lab/attack.py                    test attack; lab/normal_traffic.py baseline users; lab/wordlist.txt
lab/inventory.json               asset inventory of the lab; lab/test_credentials.json lab-only test users
lab/intel/attack_techniques.json MITRE ATT&CK (official), refreshed by scripts/fetch_attack.py
skills/soc-alert-investigation/  the Hermes skill the agent follows (SKILL.md + references/)
soc_agent/skill.py               loads the skill into every stage and installs it into the Hermes home
soc_agent/detect.py              detection rule + watcher that raises alerts
soc_agent/planner.py             Hermes plan (no tools)
soc_agent/investigate.py         Hermes evidence gathering with the soc toolset
soc_agent/tools/                 the four tools, wrapper, data access, Hermes registration
soc_agent/correlate.py           timeline, facts, ATT&CK, severity, confidence (no model)
soc_agent/assess.py              Hermes assessment with citation and proposal checks
soc_agent/response.py            human approval gate; applies approved actions on the lab portal
soc_agent/report.py              incident report (JSON + Markdown) and run history
schemas/                         alert, plan, evidence, assessment and report contracts
tests/fixtures/                  frozen synthetic dataset for offline tests only
```

## Data

- **Live path**: the lab portal's own log; client IPs are RFC 5737 documentation addresses sent as
  `X-Forwarded-For` (all lab traffic comes from localhost, so the portal acts as if behind a reverse proxy).
  Accounts use `lab.example`. Nothing outside the lab is attacked or changed.
- **Tests**: `tests/fixtures/` (synthetic, labelled MOCK where it stands in for intel).

## Known limitations

- The detector has one rule (brute force followed by success); facts come from eleven fixed rules for account
  compromise. Other attack types would need their own rules; anything uncovered is reported as unknown.
- Documentation-range IPs have no public reputation, so in the lab demo IP intel adds nothing; it does for public IPs.
- Thresholds (10 failures in 15 minutes) are fixed constants, not tuned on real traffic.
- The model sometimes skips a checklist step (1 of 4 live runs did not search the post-login window). The facts
  then show UNKNOWN and confidence drops instead of anything being guessed; facts, severity and confidence are
  always computed by code from what was actually searched.
- Approval is a CLI with a typed confirmation and a self-declared analyst name; there is no login.
- Prompts and tool results are sent to DeepSeek (third party). Real logs would need approval or a self-hosted model.

## Next steps

1. Point `search_logs` at a real SIEM API (Wazuh/Elastic) behind the same schema and wrapper.
2. More skills on the same pattern: phishing triage, malware-on-host, impossible travel.
3. Analyst login (SSO) and a small web page for reports and approvals.
4. More detection rules: impossible travel, MFA fatigue, malware on host.
5. An evaluation set of attacks to measure detection and assessment accuracy.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DEEPSEEK_API_KEY` | none (required) | DeepSeek API key, read from `.env` |
| `SOC_MODEL` | `deepseek-chat` | DeepSeek model id used by Hermes |
| `ABUSEIPDB_API_KEY` | empty | optional, enables IP reputation scores |
| `LAB_URL` | `http://127.0.0.1:8800` | where `approve` reaches the lab portal |
| `SOC_FAULTS` | empty | fault injection, e.g. `lookup_ip=timeout,search_logs=malformed` |
| `SOC_DATA` | empty | `fixtures` = use the frozen test dataset (set automatically by the tests) |
