# Architecture

## Layers

```mermaid
flowchart LR
    subgraph SIEM["Alert source (SIEM / detection) - NOT the agent"]
        R[Detection rule<br/>AUTH-BRUTE-SUCCESS] --> A[(Alert JSON<br/>data/alerts/)]
        L[(Synthetic logs<br/>data/logs/ - Day 2)]
    end

    subgraph APP["soc_agent (this repo)"]
        V[Alert validator<br/>schemas/alert.schema.json]
        P[Planner<br/>prompt + plan schema check]
        AU[(Audit trail<br/>runs/&lt;run&gt;/audit.jsonl)]
    end

    subgraph HERMES["Hermes agent - orchestration layer"]
        H[AIAgent<br/>provider: DeepSeek<br/>HERMES_HOME=.hermes_home]
        TS{{Enabled toolsets<br/>Day 1: none<br/>Day 2+: soc only}}
    end

    subgraph TOOLS["Tool layer - narrow, read-only (Day 2)"]
        T1[search_logs]
        T2[lookup_ip - MOCK intel]
        T3[search_cve - local snapshot]
        T4[get_asset_context]
    end

    subgraph HUMAN["Analyst"]
        UI[CLI now, FastAPI page later]
        APR[Approval gate - Day 4<br/>block / disable / isolate]
    end

    A --> V --> P --> H
    H --> TS -.-> TOOLS
    TOOLS -.-> L
    P --> AU
    H --> AU
    P --> UI
    UI --> APR
```

## Who does what

| Layer | Responsibility | Not its job |
|---|---|---|
| SIEM / detection | Collects logs, runs deterministic rules, raises the alert. In this prototype it is represented by a synthetic alert file and (Day 2) synthetic logs. | Interpreting or explaining the alert. |
| Hermes agent | Reads the alert, plans the investigation, decides which approved tool to call next, interprets tool results, drafts the assessment. | Detecting threats, storing logs, or acting on production systems. |
| Tool layer | Narrow functions with JSON schemas and input validation that return evidence. Read-only. | Deciding what to do with the evidence. |
| Storage / audit | Append-only JSONL per run: prompt, model output, tool calls, timestamps, decisions. | — |
| Analyst | Reviews the plan/report and approves or rejects any disruptive action. | — |

## Safety decisions made on Day 1

- **Isolated Hermes home.** `HERMES_HOME` points at `.hermes_home/` inside the repo, so no personal Hermes config, memory, persona (SOUL.md) or context files are loaded.
- **Least privilege by toolset.** The agent is built with `enabled_toolsets=[]` on Day 1: the model can only return text. From Day 2 it gets only the `soc` toolset; Hermes' built-in terminal, file, browser and web tools are never enabled.
- **Schema at both ends.** Alerts are validated before they reach the model; the model's plan is validated after. A plan that names a tool outside the approved list is rejected, and the rejection reasons are sent back once for a corrected answer.
- **No action steps.** Containment (block IP, disable account, isolate host) cannot appear as a plan step; it goes to `safety_notes` and will require analyst approval (Day 4).
- **Authorized data only.** All data is synthetic: RFC 5737 documentation IPs (203.0.113.0/24), RFC 2606 domains (example.com), invented users and hosts. Every alert carries `data_provenance`.
