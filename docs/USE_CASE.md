# Use case: triaging a suspected compromise with TraceForge

This walkthrough follows a realistic investigation using the synthetic data bundled with TraceForge. All addresses use
documentation ranges (RFC 5737) and all accounts are fictional.

## The situation

A small security team receives an alert that the VPN gateway saw an unusually long run of failed logins followed by a success
for a privileged account (`user-01`). The team has four exports and no SIEM: web-server access logs, VPN authentication logs,
firewall flows and endpoint events. Reading four files side by side, in four formats and time conventions, is slow and
error-prone. TraceForge turns the same files into one reviewable timeline.

## Who it is for

| Role | How they use it |
|---|---|
| SOC analyst (tier 1-2) | Fast first-pass triage of exported logs; evidence-linked notes and verdicts |
| Small IT / security team without a SIEM | Correlate logs from different systems on one laptop, no server to run |
| Incident-response consultant | Work on client logs locally; TLP-marked, redacted reports; encrypted case files |
| Student / trainer | Repeatable lab: synthetic data, documented rules, tests that prove each detection |

## Walkthrough

1. **Start the console** - `traceforge serve`, then click **Load sample data** (or drop in your own files).
2. **Check the evidence** - the *Evidence* tab shows, per file, the events kept, the rows dropped (for example, no parseable
   timestamp), how columns were mapped, and the SHA-256. Hashes are re-verified every time the app starts.
3. **Read the incident list** - the demo produces 555 events from 4 sources, 16 findings and 4 incidents.
   `INC-001` is **critical**: findings from all four sources share the actors `203.0.113.45` and `user-01`.
4. **Follow the timeline** - `INC-001` reads as a kill chain: web scanning and injection attempts, 22 failed logins, a successful
   login, an off-hours session, a suspicious command line on `dc01`, a new account added to Administrators, a 72 MB upload to
   `198.51.100.77`, and finally the audit log being cleared. Each step links to the exact events behind it.
5. **Judge confidence, don't assume** - the confidence score (90, *High*) lists its own factors: 8 independent rules fired, 4
   log sources agree, 6 ATT&CK tactics appear. The three smaller incidents score 30 (*Low*) because a single rule fired. The
   analyst can override the score.
6. **Record the decision** - set a verdict, add notes, tick response checklist steps and add indicators (IOCs). Every change is
   written to the hash-chained audit log.
7. **Share safely** - export a PDF, Markdown, JSON or CSV report. With `TLP:CLEAR` or `TLP:GREEN` usernames, hostnames and internal
   IPs are masked in every format. Export STIX 2.1 indicators or an ATT&CK Navigator layer for other tools, or save an
   encrypted case file.

## Headless / automation

```bash
traceforge analyze logs/* --tlp TLP:GREEN --pdf report.pdf --md report.md --stix iocs.json --attack-layer layer.json
```

## What TraceForge does not do

It analyses files you give it; it does not collect telemetry, block traffic or contain hosts, and detections are heuristics
that need an analyst's judgement. See [THREAT_MODEL.md](../THREAT_MODEL.md) and the *Known false positives* column in
[DETECTION_RULES.md](DETECTION_RULES.md).
