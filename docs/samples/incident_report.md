# Incident report IR-ALR-2026-1001_20261124T082224Z_e87d76

> **Data:** LAB (live lab portal log, real ATT&CK data, live intel APIs). Response actions apply only to the lab portal, after human approval.

| | |
|---|---|
| Alert | `ALR-2026-1001`: Repeated failed logins followed by success (AUTH-BRUTE-SUCCESS) |
| Account | `j.doe@lab.example` |
| Host | `LAB-PORTAL-01` |
| Source IPs | `203.0.113.45` |
| **Severity** | **CRITICAL** (how bad if true) |
| **Confidence** | **HIGH** (how sure we are) |
| Generated | 2026-11-24T08:23:05.398+00:00 by Hermes Agent (Nous Research) with DeepSeek; read-only `soc` toolset |

## Summary

An automated, scripted client at 203.0.113.45 guessed passwords for j.doe@lab.example, an account with no MFA. After 50 failures in roughly 8 seconds the 51st attempt succeeded (F1, F7, F8). The IP had never appeared for this account in the prior week (F2), and it also tried a.kumar@lab.example and m.lee@lab.example in the same window (F3), which fits a spray-shaped actor rather than a single-user typo. Within milliseconds of the login the session created a mailbox rule forwarding mail to an external address, read 14 files from the \\LAB-PORTAL-01\payables share, and logged out (F4, F5, F6). That is textbook post-compromise collection and exfiltration staging on a high-criticality finance asset (F10). The speed and ordering of these actions — rule creation and bulk file read in under 10 ms, immediately after success — argues strongly against a human doing this unintentionally.

## Severity rationale

- F1: brute force followed by a successful login (account access likely obtained)
- F5: external mail-forwarding rule created after the login
- F6 + F10: files read from a share using a high-criticality asset

Model's view: **critical** (agrees with the rule-based level). If true — and F1, F5 and F6 are confirmed, not inferred — an attacker obtained authenticated access to a finance account, established persistent external mail forwarding, and read a payables share on a high-criticality asset (F10). This matches the rubric's critical bar on all three counts: brute force plus success, external forwarding, and file access on a high-criticality host. The absence of public reputation for the source IP (F11) does not reduce severity, only our ability to attribute. I therefore agree with the rule-based critical rating and see no basis to downgrade.

## Confidence rationale

- all key facts were checked and every tool call succeeded

## Hypotheses

| Id | Status | Facts | Explanation |
|---|---|---|---|
| H1 | supported | F1, F2, F7, F8, F5, F6, F4 | Brute force succeeded: 50 failures then success from the same IP (F1), using a scripted python-httpx client (F7) against an account with no MFA (F8). The IP is new for this account over 7 days (F2). The session immediately created an external forwarding rule (F5), read 14 payables files (F6) and logged out (F4) — the actor held an authenticated session and used it. |
| H2 | refuted | F7, F3, F5, F6, F2 | A misconfigured client or mistyping user is implausible: the client is a scripted httpx library, not a mail app or browser (F7); the same IP also probed two other accounts (F3); and the 'correct' login was followed within milliseconds by an external forwarding rule and a bulk read of payables (F5, F6). The IP is also outside the account's usual IPs (F2/F9). |
| H3 | supported | F3, F1 | The same IP attempted a.kumar@lab.example (6 failures) and m.lee@lab.example (6 failures) in the same window alongside the 50 attempts and success on j.doe@lab.example (F3, F1). Low per-account counts on the other two accounts combined with a heavy burst on one is consistent with spraying across a small account set before concentrating on one. |
| H4 | undetermined | F1, F5, F6 | This framing is partly borne out — the post-login behaviour (F5, F6) is indeed the most damaging signal — but the premise that the successes are legitimate is contradicted by F1: access was obtained by brute force from a new, scripted source. So 'legitimate login abused afterwards' does not hold; the account was compromised, not merely misused by its owner. |

## Alternative explanations

- A security or QA scanner/pentest owned by the lab used a scripted client to test the portal and, as part of the test, wrote and cleaned up a forwarding rule and touched the payables share. [F7, F5, F6, F2, F9]. Less likely because: A sanctioned test would normally come from an expected range and would be coordinated; this IP is outside the account's usual IPs (F2, F9), the rule forwards to an external domain (billing-sync@exfil-lab.example.net, F5), and 14 real payables files were read (F6). Nothing in the evidence indicates authorization.
- A legitimate user travelling or on a new network fat-fingered their password repeatedly from a personal script and then set up forwarding for convenience before downloading payables files. [F7, F3, F1]. Less likely because: The source is a scripted httpx client, not a mail or browser client (F7); the same IP hit two other named employees (F3); and a human cannot create a rule and read 14 files in the same second as the login (F1, F4). The login time is inside working hours (F9), which is the only point in its favour, and geolocation/known-IP checks still show the IP as unfamiliar.

## Still unknown

- Whether the mail-forwarding rule is still active and whether any mail has already been forwarded to billing-sync@exfil-lab.example.net (rule existence is confirmed, its ongoing effect is not).
- Whether the 14 payables files were actually transmitted out or only read on the share — exfiltration destination is not evidenced in F6.
- Whether a.kumar@lab.example and m.lee@lab.example were later targeted successfully outside the alert window (F3 only covers the window).
- Whether other accounts besides the three named were targeted by 203.0.113.45 — the search appears scoped to this window and account set.
- The content/sensitivity of the 14 payables files and whether that share holds regulated or financial data requiring notification.
- The real-world identity of 203.0.113.45: it is an RFC 5737 documentation address, so no public reputation exists (F11) and geolocation/ownership cannot be established.
- Whether any other accounts in the tenant lack MFA in the same way as j.doe@lab.example (only this account was checked).

## Facts (computed from tool results, not by the model)

| Id | Status | Statement | Evidence |
|---|---|---|---|
| F1 | confirmed | 50 failed logins for j.doe@lab.example from 203.0.113.45, then a successful login from the same IP at 2026-11-24T08:03:47.309Z (0s after the last failure). | `lab/state/events.jsonl#L22`, `lab/state/events.jsonl#L71`, `lab/state/events.jsonl#L72` |
| F2 | confirmed | 203.0.113.45 has no history for j.doe@lab.example in the searched look-back (2026-11-17 to 2026-11-24): the IP is new for this account. | none |
| F3 | confirmed | 203.0.113.45 also targeted 2 other account(s) in the same window: a.kumar@lab.example (6 failed, 0 successful), m.lee@lab.example (6 failed, 0 successful). | `lab/state/events.jsonl#L10`, `lab/state/events.jsonl#L16` |
| F4 | confirmed | After the login, the same IP session performed: file_access, logout, mailbox_rule_created. | `lab/state/events.jsonl#L73`, `lab/state/events.jsonl#L74`, `lab/state/events.jsonl#L75` |
| F5 | confirmed | A mailbox rule forwarding mail to an external address (billing-sync@exfil-lab.example.net) was created at 2026-11-24T08:03:47.313Z. | `lab/state/events.jsonl#L73` |
| F6 | confirmed | Files were read from \\LAB-PORTAL-01\payables (14 files, 3351495 bytes) at 2026-11-24T08:03:47.316Z. | `lab/state/events.jsonl#L74` |
| F7 | confirmed | Logins used a scripted client user agent (python-httpx/0.28.1), not a browser or mail app. | `lab/state/events.jsonl#L22` |
| F8 | confirmed | j.doe@lab.example is not enrolled in MFA (a password alone was enough to log in). | `lab/inventory.json#j.doe@lab.example` |
| F9 | confirmed | Login at 08:03 UTC is inside usual hours 03:30-12:30; 203.0.113.45 is not one of the account's usual IPs. | `lab/inventory.json#j.doe@lab.example` |
| F10 | confirmed | LAB-PORTAL-01 is a high-criticality web portal and payables file share (Finance). | `lab/inventory.json#LAB-PORTAL-01` |
| F11 | not_observed | 203.0.113.45 is a documentation range (RFC 5737) address: no public reputation exists, so none was used. | `lookup_ip#203.0.113.45` |

## MITRE ATT&CK (only where a confirmed fact supports it)

- **T1110.001** Brute Force: Password Guessing <- F1
- **T1110.003** Brute Force: Password Spraying <- F3
- **T1078** Valid Accounts <- F1
- **T1114.003** Email Collection: Email Forwarding Rule <- F5
- **T1039** Data from Network Shared Drive <- F6

## Timeline

| Time (UTC) | Count | Event | Account | Source IP | Evidence |
|---|---|---|---|---|---|
| 2026-11-24 08:02:57 | 1 | auth_success | j.doe@lab.example | 198.51.100.10 | `lab/state/events.jsonl#L1` |
| 2026-11-24 08:02:57 | 1 | logout | j.doe@lab.example | 198.51.100.10 | `lab/state/events.jsonl#L2` |
| 2026-11-24 08:03:37 to 08:03:38 | 6 | auth_failure | a.kumar@lab.example | 203.0.113.45 | `lab/state/events.jsonl#L10` (+1 more) |
| 2026-11-24 08:03:38 to 08:03:39 | 6 | auth_failure | m.lee@lab.example | 203.0.113.45 | `lab/state/events.jsonl#L16` (+1 more) |
| 2026-11-24 08:03:39 to 08:03:47 | 50 | auth_failure | j.doe@lab.example | 203.0.113.45 | `lab/state/events.jsonl#L22` (+1 more) |
| 2026-11-24 08:03:47 | 1 | auth_success | j.doe@lab.example | 203.0.113.45 | `lab/state/events.jsonl#L72` |
| 2026-11-24 08:03:47 | 1 | mailbox_rule_created | j.doe@lab.example | 203.0.113.45 | `lab/state/events.jsonl#L73` |
| 2026-11-24 08:03:47 | 1 | file_access | j.doe@lab.example | 203.0.113.45 | `lab/state/events.jsonl#L74` |
| 2026-11-24 08:03:47 | 1 | logout | j.doe@lab.example | 203.0.113.45 | `lab/state/events.jsonl#L75` |

## Response actions (human approval required)

| Id | Action | Target | Facts | Status | Decided by |
|---|---|---|---|---|---|
| A1 | block_ip | `203.0.113.45` | F1, F3, F7 | **pending_approval** | - |
| A2 | disable_account | `j.doe@lab.example` | F1, F5, F6, F8 | **pending_approval** | - |

- A1: Confirmed brute force followed by a successful login from this exact IP (F1), using a scripted client (F7), and the same IP also attempted two other accounts (F3). Blocking the alert source IP stops further attempts against the other accounts and any reuse of the session from this endpoint.
- A2: The account was compromised by brute force with no MFA (F1, F8) and the attacker session used it to create external forwarding (F5) and read payables files (F6). Disabling the account cuts off further use of the stolen session and is required before the forwarding rule and credential can be safely remediated.

Approve with `python -m soc_agent approve runs/ALR-2026-1001_20261124T082224Z_e87d76 <id> --analyst <name>` (interactive terminal only). Actions apply only to the lab portal.

## Tool-call history

| # | Tool | OK | Reason |
|---|---|---|---|
| 1 | search_logs | yes | Step 1: confirm the failed-login count, timestamps, and the successful login in raw events for the alert account and host in the alert window. |
| 2 | search_logs | yes | Step 2: check whether source IP 203.0.113.45 targeted other accounts or hosts in the alert window (spray vs single-account). |
| 3 | get_asset_context | yes | Step 5: obtain account owner/role/privilege and MFA status plus host criticality to judge impact of the successful login. |
| 4 | lookup_ip | yes | Step 6: characterise source IP 203.0.113.45 reputation/infrastructure, expecting a reserved documentation range result. |
| 5 | search_cve | yes | Step 7: map the observed failed-then-successful authentication pattern to official ATT&CK technique definitions. |
| 6 | search_logs | yes | Step 3: determine what the session did after the claimed 08:03:47Z success, including the success event itself, for 30 minutes. |
| 7 | search_logs | yes | Step 4: establish a 7-day pre-alert baseline for the account and whether 203.0.113.45 was previously seen. |
| 8 | search_cve | yes | Step 7 follow-up: the keyword query returned unrelated techniques, so retrieve the brute force technique T1110 directly. |

## Audit artifacts (in this run folder)

- audit_log: `audit.jsonl`
- tool_trace: `tool_trace.json`
- timeline: `timeline.json`
- evidence: `evidence.json`
- investigation: `investigation.json`
- approvals: `approvals.json`

## Limitations

- The monitored system is a lab portal we own; client IPs are RFC 5737 documentation addresses sent via X-Forwarded-For.
- Documentation-range IPs have no public reputation, so IP intel adds context only for public IPs.
- Response actions change only the lab portal, and only after a named analyst approves them.
- Facts are computed by fixed rules; behaviour outside those rules is reported as unknown, not inferred.
