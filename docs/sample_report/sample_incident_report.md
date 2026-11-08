# TraceForge Incident Report - Sample incident

| | |
|---|---|
| Report ID | TF-20261105-7C271422 |
| Status | **DRAFT** |
| Classification | TLP:AMBER - Limited disclosure. Recipients may share only within their organisation and with clients who need to know. |
| Prepared by | Sample Analyst |
| Generated | 2026-11-05 10:25 UTC |
| Tool | TraceForge v1.2.0 |

> **DRAFT - not reviewed.** 4 of 4 incident(s) have no analyst verdict (INC-001, INC-002, INC-003, INC-004).

## 1. Executive summary

- 555 events from 4 source(s) were analysed, covering 2026-03-13 07:00 to 2026-03-14 03:14 UTC.
- 17 rule finding(s) were correlated into 4 incident(s): 1 critical, 1 high, 2 medium.
- Highest priority: INC-001 - Multi-stage activity involving 198.51.100.77, 203.0.113.45, user-01. Window 2026-03-13 21:58 to 23:52 UTC; ATT&CK tactics observed: Reconnaissance, Initial Access, Credential Access, Execution, Persistence, Exfiltration; confidence High (95/100); analyst verdict: Unreviewed.
- 1 indicator(s) of compromise are recorded for this case.

### Key observations

| Stage | Severity | Observation | Refs |
|---|---|---|---|
| Reconnaissance | medium | 192.0.2.50 probed 40 distinct ports on 1 destination(s) in 39s. (+1 more reconnaissance finding) | F002, F003 |
| Initial Access | high | SQL injection pattern in 4 request(s) from 203.0.113.45. 1 returned HTTP 2xx - verify whether the payload had any effect. (+5 more initial access findings) | F001, F004, F005, F006... |
| Credential Access | high | 22 failed logins from 203.0.113.45 against 1 account(s) over 4m 12s. (+1 more credential access finding) | F007, F017 |
| Execution | high | Encoded PowerShell on dc01: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFc (+1 more execution finding) | F010, F011 |
| Persistence | critical | Audit log cleared on dc01 (1 event(s)): The audit log was cleared (+2 more persistence findings) | F012, F013, F016 |
| Exfiltration | high | 72.2 MB sent from 10.0.5.20 to external 198.51.100.77 over 29m 45s (6 flow(s)). | F015 |

## 2. Scope and evidence integrity

- Evidence re-verified 2026-11-05 10:25:16 UTC: all stored files match their SHA-256.
- Audit log: 7 entries, hash chain intact, head f11cdb07df89c05192b2dae3e61ff7eb423743e0064f82fe56f2891af6dfe580.

| File | SHA-256 | Rows kept |
|---|---|---|
| endpoint_events.json | `8c2b69bee66f83481ef839fdc8eebe3fbb63047a5d07b169b243057056c56b19` | 6/6 |
| firewall.csv | `7917a8b1f71554018c5af0c19d6244215d1b07ea485d91b6e094d564c657d2fa` | 86/86 |
| vpn_auth.csv | `da24574c53e0bb9a2d0dec5b6f22bb1868af95b68a3149570293c75a1193fd4b` | 134/134 |
| web_access.json | `66e4df55ffefb9f517f3bccda1d44161b1384267df82450c69f7a8d844f46938` | 329/329 |

## 3. Affected assets

| Type | Entity | Incidents | Events |
|---|---|---|---|
| Account | `user-01` | INC-001 | 30 |
| Account | `user-02` | INC-003 | 11 |
| Host | `dc01` | INC-001 | 6 |
| Internal IP | `10.0.5.20` | INC-001 | 12 |
| Internal IP | `10.0.2.21` | INC-003 | 9 |
| External IP | `203.0.113.45` | INC-001 | 91 |
| External IP | `192.0.2.50` | INC-004 | 40 |
| External IP | `198.51.100.23` | INC-002 | 13 |
| External IP | `198.51.100.77` | INC-001 | 6 |
| External IP | `192.0.2.77` | INC-003 | 1 |

## 4. Incident analysis

### INC-001 - Multi-stage activity involving 198.51.100.77, 203.0.113.45, user-01

14 detection finding(s) from 4 log source(s) were correlated between 2026-03-13 21:58 and 23:52 UTC (1h 54m). Observed kill-chain progression: Reconnaissance → Initial Access → Credential Access → Execution → Persistence → Exfiltration → IOC match.
- **Severity:** critical  |  **Confidence:** High (95/100)  |  **Verdict:** Unreviewed
- **Window:** 2026-03-13 21:58:00 to 23:52:20 UTC
- **IP addresses:** 203.0.113.45, 10.0.5.20, 198.51.100.77
- **Accounts:** user-01
- **Hosts:** dc01
- **ATT&CK:** T1048, T1059, T1078, T1110, T1136 / T1098 / T1070.001, T1190, T1595.002

#### Timeline

| Time (UTC) | Stage | Observation | Ref |
|---|---|---|---|
| 2026-03-13 21:58:00 UTC | Reconnaissance | 62 client-error responses (404) for 203.0.113.45 against web01 in 3m 03s. | F003 |
| 2026-03-13 22:03:10 UTC | Initial Access | SQL injection pattern in 4 request(s) from 203.0.113.45. 1 returned HTTP 2xx - verify whether the payload had any effect. | F004 |
| 2026-03-13 22:03:50 UTC | Initial Access | Cross-site scripting pattern in 1 request(s) from 203.0.113.45. No 2xx responses seen. | F005 |
| 2026-03-13 22:04:10 UTC | Initial Access | Path traversal pattern in 1 request(s) from 203.0.113.45. No 2xx responses seen. | F006 |
| 2026-03-13 22:15:00 UTC | Credential Access | 22 failed logins from 203.0.113.45 against 1 account(s) over 4m 12s. | F007 |
| 2026-03-13 22:15:00 UTC | Initial Access | Account 'user-01' logged in from 203.0.113.45 after 22 failed attempts within 30 min. | F008 |
| 2026-03-13 22:20:11 UTC | Initial Access | 'user-01' logged in from 203.0.113.45 at 22:20 UTC on 2026-03-13 (outside 07:00-19:00 UTC). | F009 |
| 2026-03-13 22:24:40 UTC | Execution | Discovery / enumeration on dc01: whoami /all | F010 |
| 2026-03-13 22:27:03 UTC | Execution | Encoded PowerShell on dc01: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFc | F011 |
| 2026-03-13 22:31:12 UTC | Persistence | Account created on dc01 (1 event(s)): A user account was created: svc_backup2 | F012 |
| 2026-03-13 22:31:40 UTC | Persistence | Added to privileged group on dc01 (1 event(s)): svc_backup2 was added to the Administrators group | F013 |
| 2026-03-13 23:10:20 UTC | IOC match | IOC ipv4 '198.51.100.77' appears in 6 event(s) - note: sample. | F014 |
| 2026-03-13 23:10:20 UTC | Exfiltration | 72.2 MB sent from 10.0.5.20 to external 198.51.100.77 over 29m 45s (6 flow(s)). | F015 |
| 2026-03-13 23:52:20 UTC | Persistence | Audit log cleared on dc01 (1 event(s)): The audit log was cleared | F016 |

#### Confidence factors

- Baseline for any rule-based finding: +20
- 9 independent detection rule(s) fired: +30
- Corroborated by 4 different log sources: +15
- Activity spans 6 ATT&CK tactics (kill-chain progression): +15
- Evidence of success/impact (login after failures, persistence or data transfer): +10
- Matches an analyst-recorded IOC: +10

#### Response actions

**Immediate containment**

- [ ] Block the destination IP/domain and capture network evidence.
- [ ] Disable any account or group membership that was not change-approved.
- [ ] Isolate the host from the network (EDR containment) pending triage.
- [ ] Block or rate-limit the source IP at the firewall / WAF.
- [ ] Treat the account as potentially compromised: disable it and revoke active sessions/tokens.
- [ ] Block the source at the WAF and review responses (HTTP 200 on a payload warrants deeper review).
- [ ] Rate-limit or block the scanning IP.

**Investigation and scoping**

- [ ] Scope the activity: search all other log sources for the same indicator.
- [ ] Identify what data was on the source host and assess breach-notification duties.
- [ ] Preserve the affected host's logs/disk image before cleanup (evidence).
- [ ] Collect the process tree, memory and the decoded payload for analysis.
- [ ] Hunt for the same command pattern on other hosts.
- [ ] Verify the login with the account owner or on-call roster.
- [ ] Review everything the account did after the successful login.
- [ ] Confirm no discovered path exposes sensitive content.

**Recovery and hardening**

- [ ] Restore audit logging and forward logs off-host so they cannot be wiped locally.
- [ ] Enforce account lockout and MFA on the targeted service.
- [ ] Reset credentials and re-enrol MFA after the account is verified with its owner.
- [ ] Patch or harden the targeted application and review its database/app logs.

### INC-002 - Credential Access activity involving 198.51.100.23

1 detection finding(s) from 1 log source(s) were correlated between 2026-03-14 03:10 and 03:14 UTC (4m). Observed kill-chain progression: Credential Access.
- **Severity:** high  |  **Confidence:** Low (30/100)  |  **Verdict:** Unreviewed
- **Window:** 2026-03-14 03:10:00 to 03:14:00 UTC
- **IP addresses:** 198.51.100.23
- **Accounts:** -
- **Hosts:** -
- **ATT&CK:** T1110.003

#### Timeline

| Time (UTC) | Stage | Observation | Ref |
|---|---|---|---|
| 2026-03-14 03:10:00 UTC | Credential Access | 198.51.100.23 failed against 13 distinct accounts (13 attempts) over 4m 00s. | F017 |

#### Confidence factors

- Baseline for any rule-based finding: +20
- 1 independent detection rule(s) fired: +10

#### Response actions

**Immediate containment**

- [ ] Block the source IP and review all accounts it targeted.
- [ ] Force password reset for any targeted account that later logged in successfully.

**Recovery and hardening**

- [ ] Enable MFA and smart-lockout on the authentication endpoint.

### INC-003 - Initial Access activity involving 192.0.2.77, user-02

1 detection finding(s) from 1 log source(s) were correlated between 2026-03-13 08:37 and 13:33 UTC (4h 56m). Observed kill-chain progression: Initial Access.
- **Severity:** medium  |  **Confidence:** Low (30/100)  |  **Verdict:** Unreviewed
- **Window:** 2026-03-13 08:37:33 to 13:33:38 UTC
- **IP addresses:** 10.0.2.21, 192.0.2.77
- **Accounts:** user-02
- **Hosts:** -
- **ATT&CK:** T1078

#### Timeline

| Time (UTC) | Stage | Observation | Ref |
|---|---|---|---|
| 2026-03-13 08:37:33 UTC | Initial Access | Account 'user-02' authenticated from 2 IPs (10.0.2.21, 192.0.2.77) within 60 min. | F001 |

#### Confidence factors

- Baseline for any rule-based finding: +20
- 1 independent detection rule(s) fired: +10

#### Response actions

**Immediate containment**

- [ ] Revoke sessions and require re-authentication if not.

**Investigation and scoping**

- [ ] Confirm with the user whether both locations are legitimate.

### INC-004 - Reconnaissance activity involving 192.0.2.50

1 detection finding(s) from 1 log source(s) were correlated between 2026-03-13 14:20 and 14:20 UTC (0m). Observed kill-chain progression: Reconnaissance.
- **Severity:** medium  |  **Confidence:** Low (30/100)  |  **Verdict:** Unreviewed
- **Window:** 2026-03-13 14:20:01 to 14:20:40 UTC
- **IP addresses:** 192.0.2.50
- **Accounts:** -
- **Hosts:** -
- **ATT&CK:** T1046

#### Timeline

| Time (UTC) | Stage | Observation | Ref |
|---|---|---|---|
| 2026-03-13 14:20:01 UTC | Reconnaissance | 192.0.2.50 probed 40 distinct ports on 1 destination(s) in 39s. | F002 |

#### Confidence factors

- Baseline for any rule-based finding: +20
- 1 independent detection rule(s) fired: +10

#### Response actions

**Immediate containment**

- [ ] Block the scanning IP.

**Investigation and scoping**

- [ ] Review which scanned services must be exposed at all.

## 5. Indicators of compromise

| Type | Value | Note |
|---|---|---|
| ipv4 | `198.51.100.77` | sample |

## Appendix A. Findings register

| ID | Start (UTC) | Rule | Severity | ATT&CK | Events | Incident |
|---|---|---|---|---|---|---|
| F001 | 2026-03-13 08:37:33 | Account used from multiple IPs - Account 'user-02' authenticated from 2 IPs (10.0.2.21, 192.0.2.77) within 60 min. | medium | T1078 | 10 | INC-003 |
| F002 | 2026-03-13 14:20:01 | Port scan - 192.0.2.50 probed 40 distinct ports on 1 destination(s) in 39s. | medium | T1046 | 40 | INC-004 |
| F003 | 2026-03-13 21:58:00 | Web scanning / forced browsing - 62 client-error responses (404) for 203.0.113.45 against web01 in 3m 03s. | medium | T1595.002 | 62 | INC-001 |
| F004 | 2026-03-13 22:03:10 | Web attack payload in request - SQL injection pattern in 4 request(s) from 203.0.113.45. 1 returned HTTP 2xx - verify whether the payload had any effect. | high | T1190 | 4 | INC-001 |
| F005 | 2026-03-13 22:03:50 | Web attack payload in request - Cross-site scripting pattern in 1 request(s) from 203.0.113.45. No 2xx responses seen. | high | T1190 | 1 | INC-001 |
| F006 | 2026-03-13 22:04:10 | Web attack payload in request - Path traversal pattern in 1 request(s) from 203.0.113.45. No 2xx responses seen. | high | T1190 | 1 | INC-001 |
| F007 | 2026-03-13 22:15:00 | Repeated failed logins (brute force) - 22 failed logins from 203.0.113.45 against 1 account(s) over 4m 12s. | high | T1110 | 22 | INC-001 |
| F008 | 2026-03-13 22:15:00 | Successful login after failures - Account 'user-01' logged in from 203.0.113.45 after 22 failed attempts within 30 min. | high | T1078 | 23 | INC-001 |
| F009 | 2026-03-13 22:20:11 | Off-hours login - 'user-01' logged in from 203.0.113.45 at 22:20 UTC on 2026-03-13 (outside 07:00-19:00 UTC). | low | T1078 | 1 | INC-001 |
| F010 | 2026-03-13 22:24:40 | Suspicious command line - Discovery / enumeration on dc01: whoami /all | medium | T1059 | 2 | INC-001 |
| F011 | 2026-03-13 22:27:03 | Suspicious command line - Encoded PowerShell on dc01: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFc | high | T1059 | 1 | INC-001 |
| F012 | 2026-03-13 22:31:12 | Sensitive account / audit activity - Account created on dc01 (1 event(s)): A user account was created: svc_backup2 | high | T1136 / T1098 / T1070.001 | 1 | INC-001 |
| F013 | 2026-03-13 22:31:40 | Sensitive account / audit activity - Added to privileged group on dc01 (1 event(s)): svc_backup2 was added to the Administrators group | high | T1136 / T1098 / T1070.001 | 1 | INC-001 |
| F014 | 2026-03-13 23:10:20 | Event matches recorded IOC - IOC ipv4 '198.51.100.77' appears in 6 event(s) - note: sample. | high | n/a | 6 | INC-001 |
| F015 | 2026-03-13 23:10:20 | Large outbound transfer - 72.2 MB sent from 10.0.5.20 to external 198.51.100.77 over 29m 45s (6 flow(s)). | high | T1048 | 6 | INC-001 |
| F016 | 2026-03-13 23:52:20 | Sensitive account / audit activity - Audit log cleared on dc01 (1 event(s)): The audit log was cleared | critical | T1136 / T1098 / T1070.001 | 1 | INC-001 |
| F017 | 2026-03-14 03:10:00 | Password spraying - 198.51.100.23 failed against 13 distinct accounts (13 attempts) over 4m 00s. | high | T1110.003 | 13 | INC-002 |

## Appendix B. MITRE ATT&CK techniques observed

| Technique | Name | Stage | Findings |
|---|---|---|---|
| T1046 | Network Service Discovery | Reconnaissance | 1 |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | 1 |
| T1059 | Command and Scripting Interpreter | Execution | 2 |
| T1070.001 | Clear Windows Event Logs | Persistence | 3 |
| T1078 | Valid Accounts | Initial Access | 3 |
| T1098 | Account Manipulation | Persistence | 3 |
| T1110 | Brute Force | Credential Access | 1 |
| T1110.003 | Password Spraying | Credential Access | 1 |
| T1136 | Create Account | Persistence | 3 |
| T1190 | Exploit Public-Facing Application | Initial Access | 3 |
| T1595.002 | Vulnerability Scanning | Reconnaissance | 1 |

## Appendix C. Methodology, definitions and limitations

- Pipeline: import (CSV, JSON/NDJSON, text logs, Windows Event XML and Sysmon, Zeek, AWS CloudTrail, ZIP/gzip bundles) > normalise timestamps to UTC, IP addresses, usernames and event types > rule-based detection > correlation of findings that share an IP, account or host within a configurable time gap > transparent scoring.
- TraceForge analyses only the files supplied. It is not a live SIEM and does not claim to detect attacks that are absent from the evidence or that no enabled rule covers.
- Timestamps without a timezone are interpreted as UTC. Rows without a parseable timestamp are dropped and counted, never guessed. No GeoIP or threat-intelligence feeds are queried; IOC matching uses only indicators recorded by the analyst.
- Severity and confidence are heuristics. A finding can be a false positive (for example a user on a mobile hotspot); the analyst verdict recorded in this report takes precedence.
- Built-in rules enabled: 17 of 17. Rules that produced findings in this run: Account used from multiple IPs, Event matches recorded IOC, Large outbound transfer, Off-hours login, Password spraying, Port scan, Repeated failed logins (brute force), Sensitive account / audit activity, Successful login after failures, Suspicious command line, Web attack payload in request, Web scanning / forced browsing.

**Severity (indicative):** *Critical* - Activity consistent with an active, multi-stage compromise. Raised automatically when an incident spans three or more ATT&CK tactics and contains at least one High finding. Respond immediately. *High* - Likely malicious activity that should be investigated promptly. *Medium* - Suspicious activity that needs validation; may be benign. *Low / Info* - Weak signal or context. Usually benign on its own.
