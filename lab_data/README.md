# TraceForge scenario pack

Synthetic, deterministic log files that exercise **every supported import format** and **every detection rule**.
Use them to learn the tool, to demo it, or as regression fixtures. All public IPs use RFC 5737 documentation ranges,
domains use `example.test`, and every account and host is fictional.

Regenerate with `python scripts/generate_scenario_pack.py` (CI fails if the committed files drift).

## Fastest path: one file, every rule

```bash
traceforge analyze lab_data/01_all_scenarios.csv --ioc-file lab_data/iocs.txt --sigma lab_data/sigma_rules
# 152 events | 42 findings | 18 incidents  (all 17 built-in rules + Sigma, 1 unsupported Sigma rule skipped with a reason)
```

In the web console: **Add logs** → pick `01_all_scenarios.csv`, then **IOCs** → *Bulk add* → paste `iocs.txt`, then
**Settings** → *Sigma* → import the files in `sigma_rules/`.

## The files

| File | Import path exercised | Events | Rules it triggers |
|---|---|---:|---|
| `01_all_scenarios.csv` | Canonical CSV | 152 | **all 17 built-in rules** + `sigma_match` (with `iocs.txt` and `sigma_rules/`) |
| `02_web_access.log` | Apache/nginx combined access log (text parser) | 50 | `web_scan`, `web_attack_payload` (SQLi, XSS, traversal, command injection, Log4Shell) |
| `03_ssh_auth_syslog.log` | Classic syslog / `auth.log`, no year in timestamps | 17 | `brute_force`, `password_spray`, `success_after_failures`, `off_hours_login`, `sensitive_activity` |
| `04_firewall_keyvalue.log` | `key=value` firewall lines (text parser) | 29 | `port_scan`, `large_outbound` |
| `05_windows_security_sysmon.xml` | Windows Event XML: Security 4624/4625/4720/4732/4698/1102/7045 + Sysmon 1/3/13 | 32 | `brute_force`, `success_after_failures`, `lateral_movement`, `sensitive_activity`, `persistence_mechanism`, `suspicious_command`, `office_spawns_shell`, `beaconing` |
| `06_zeek_conn.log` | Zeek TSV (`#fields` header) | 40 | `beaconing`, `port_scan` |
| `07_cloudtrail.json` | AWS CloudTrail (`Records` array) | 12 | `brute_force`, `success_after_failures`, `sensitive_activity` (CreateUser, AdministratorAccess, StopLogging) |
| `08_ecs_nested.ndjson` | Nested JSON, one object per line (`source.ip`, `user.name`, `event.action`) | 14 | `brute_force`, `success_after_failures`, `off_hours_login` |
| `09_splunk_style_epoch.csv` | Non-canonical column aliases (`_time`, `src`, `dest_ip`, `account`, `action`, `bytes`) and epoch times | 26 | `port_scan`, `brute_force`, `large_outbound` |
| `10_data_quality_edge_cases.csv` | Data-quality handling | 13 read, 9 kept | none (benign); see below |
| `11_bundle.zip` | ZIP archive holding a web log and a firewall log | 79 | `web_scan`, `web_attack_payload`, `port_scan`, `large_outbound` |
| `12_ssh_auth_syslog.log.gz` | gzip-compressed log | 17 | identical to `03_ssh_auth_syslog.log` |
| `iocs.txt` | Bulk IOC list: IPv4, domain, MD5, username, URL, e-mail | 6 | `ioc_match` when loaded with files 01-03 or 05 |
| `sigma_rules/` | Two supported Sigma rules and one the importer must skip | 3 | `sigma_match` (rclone copy; outbound SSH from a private address) |

## Scenario map for `01_all_scenarios.csv`

| Rule | Scenario in the file | Threshold crossed |
|---|---|---|
| `brute_force` | 8 failed logins for `user-03` from `203.0.113.10` in 3.5 minutes | 5 failures / 10 min |
| `password_spray` | `203.0.113.11` fails against 7 different accounts | 5 distinct users / 15 min |
| `success_after_failures` | 4 failures then a success for `user-04` from `198.51.100.20` | 3 failures / 30 min |
| `multi_ip_login` | `user-05` succeeds from `10.0.1.15`, then from external `192.0.2.99` 20 minutes later | 2 IPs, one external / 60 min |
| `off_hours_login` | External login at 02:40 UTC (Tue) and a privileged `admin` login on Saturday | outside 07:00-19:00, weekends |
| `sensitive_activity` | Account created, added to Administrators, audit log cleared | any occurrence |
| `mfa_fatigue` | 6 denied MFA prompts then a successful login for `user-07` | 5 denials / 10 min (critical when a login follows) |
| `web_scan` | 20 responses of 403/404 to `203.0.113.30` in two minutes | 15 errors / 5 min |
| `web_attack_payload` | SQL injection, XSS, path traversal, command injection, Log4Shell | pattern match |
| `suspicious_command` | Encoded PowerShell, download cradle, credential dumping, shadow-copy deletion, reverse shell, domain enumeration | pattern match |
| `persistence_mechanism` | `schtasks /create`, `sc create`, `reg add ...\Run`, service-install event | pattern match |
| `office_spawns_shell` | `WINWORD.EXE` starts `cmd.exe` | parent/child pair |
| `lateral_movement` | `svc-backup` logs in to 5 hosts in 5 minutes; PsExec to `srv-db01` | 4 hosts / 15 min; pattern match |
| `port_scan` | `203.0.113.40` probes 25 distinct ports in 100 seconds | 15 ports / 5 min |
| `large_outbound` | 3 x 25 MB flows to `198.51.100.200` in 16 minutes | 50 MB / 60 min |
| `beaconing` | `10.0.1.42` calls `198.51.100.150:8443` 12 times, every 60 s +/- 2 s | 8 connections, jitter <= 20 % |
| `ioc_match` | Events containing the IP, domain, hash, username and URL from `iocs.txt` | exact match |
| `sigma_match` | `rclone.exe copy ...` and an outbound SSH flow | the two Sigma rules |

Thirty benign logins are mixed in so the rules have something to ignore.

## What `10_data_quality_edge_cases.csv` teaches

| Row | Behaviour |
|---|---|
| Valid row, extra columns | Kept; `extra_notes` and `ticket_id` are listed as unmapped columns |
| `2026-03-10 09:01:00` | Space separator accepted |
| `2026-03-10T14:32:00+05:30` | Converted to UTC (09:02Z) |
| `not-a-date` and an empty timestamp | Counted and dropped; time is never invented |
| Apache-style stamp or epoch string in a CSV `timestamp` column | Not parsed: counted and dropped |
| `999.999.1.1` as source IP | Event kept, IP cleared and counted as invalid |
| Row with no network fields | Kept |
| IPv6 source `2001:db8::1` | Kept |
| `  USER-09  ` / `LOGIN_SUCCESS` | Trimmed and lower-cased |
| Quoted comma, unicode user name | Kept intact |

Expected data-quality report: **13 read, 9 kept, 4 bad timestamps, 1 invalid IP**.

## Try these experiments

1. Lower `brute_force.failures` to 3 in a thresholds JSON file and re-run `02`/`03`: more findings appear.
2. Run `traceforge analyze lab_data/01_all_scenarios.csv --fail-on high; echo $?` to see exit status `2` (the severity gate).
3. Load only `06_zeek_conn.log`, then add `05_windows_security_sysmon.xml`: watch correlation merge findings that share an actor.
4. Mark a report `TLP:GREEN` and compare the masked output with `TLP:AMBER`.
