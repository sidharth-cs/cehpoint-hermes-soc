# Fact rules (as implemented in soc_agent/correlate.py)

| Fact | Confirmed when | Unknown when |
|---|---|---|
| F1 | >= 10 failed logins for the account from the alert IP in the window, then a success from that IP | the window was not searched |
| F2 | no earlier events for this account from the IP in a searched look-back of >= 7 days | look-back < 7 days |
| F3 | the IP also targeted other accounts in the window | the IP was not searched for the window |
| F4 | the same IP's session did anything after the login | < 30 minutes after the login searched |
| F5 | a mailbox rule forwarding outside the account's domain was created after the login | as F4 |
| F6 | files were read after the login | as F4 |
| F7 | a login used a scripted client (python-requests, python-httpx, curl, hydra, ...) | no user agent logged |
| F8 | the account is not enrolled in MFA | no asset context |
| F9 | the login was outside usual hours or from an IP not in the account's usual list | no asset context |
| F10 | host criticality known (always confirmed when found) | no asset context |
| F11 | intel rates the IP malicious/suspicious (not_observed for reserved ranges or clean) | lookup failed or IP unknown to the source |

Severity: F1 confirmed = high; + F5, or F6 with high/critical F10, or a privileged account = critical;
>= 10 failures without success = medium; F1 unknown = medium; otherwise low.

Confidence: one point per unknown key fact (F1, F2, F3, F4, F8, F11), one for any tool failure, one for the
F1-vs-F9 conflict (brute force but a usual IP at usual hours). 0 = high, 1-2 = medium, 3+ = low.

Threat facts that may justify a disruptive proposal: F1, F3, F5, F7.
