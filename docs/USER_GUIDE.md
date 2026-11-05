# User guide

## 0. Start an investigation
The first screen has two steps: **1. Name your investigation** (and yourself as analyst) and **2. Add your log files**. The name is the title of your report. You can change it any time by clicking the **Investigation** name at the top right, which also holds **New investigation…** to start again from a blank page (it warns you first and offers to download the current case file).

## 1. Import evidence
Click **Add logs** (top right, always visible) or drop files anywhere on the window. You can add files at any time, one after another or several at once; they are merged onto one timeline. The **Evidence** tab lists every file with its event count, time range, any problems found, how its columns were read and its SHA-256, and lets you **remove** a single file (findings and incidents recalculate; your notes and IOCs are kept).

- If a file can't be read, you get a plain reason (for example "no timestamp column found") and the other files in the same upload are still added.
- A file you already imported is skipped; a different file with the same name is kept as `name (2)`.
- If the synthetic sample is loaded, TraceForge asks whether to **replace** it with your files or **keep** it alongside.

Supported: `.csv`, `.json`, `.jsonl`, `.ndjson`, and raw text logs (`.log`, `.txt`): Apache/nginx access logs, syslog and `auth.log` (sshd logins, `useradd`, `usermod`), firewall lines such as UFW (`SRC=... DST=... DPT=...`) and any line starting with an ISO timestamp. Structured files are mapped by column name, so different sources can be mixed. Classic syslog lines carry no year, so the current year is assumed.

| Canonical field | Recognised column names (examples) |
|---|---|
| timestamp | `timestamp`, `time`, `@timestamp`, `datetime`, `_time`, `epoch` (seconds or ms are auto-detected) |
| src_ip / dst_ip | `src_ip`, `source_ip`, `client_ip`, `IpAddress`, `dst`, `dest_ip`, nested `source.ip` |
| user | `user`, `username`, `TargetUserName`, nested `user.name` (DOMAIN\\ and @domain are stripped) |
| event_type | `event_type`, `event`, `action`, `EventID`, nested `event.action` |
| host, message, url, status_code, bytes_out, dst_port, command | `host`/`Computer`, `message`, `uri`, `status`, `bytes_sent`, `dport`, `process.command_line` |

Open the **Evidence** tab (or **Dashboard -> Data quality**) to confirm the mapping, see dropped rows and copy each file's SHA-256.

Timestamps without a timezone are treated as UTC. A file with no timestamp column is rejected with an explanation.

## 2. Review findings
**Findings** lists every rule hit. Select a row to see the exact evidence events and the suggested response. Tune thresholds in **Settings**; everything recalculates immediately.

## 3. Reconstruct incidents
**Incidents** is a three-pane workbench: incident cards on the left (sort by severity, time or confidence); the selected incident's event timeline with a severity histogram in the middle (click a bar to zoom, search, or show only alerted events); and on the right the Summary, Actions, Notes and IOCs tabs plus the raw evidence of the selected event. Then:
1. Add the candidate IOCs you agree with.
2. Set the state with **Change State** (Investigating, Needs escalation, True positive, False positive, Benign true positive).
3. Override the confidence if your analysis differs and record a note.

Tip: in the sample data, INC-003 (an account used from a mobile hotspot) is a good example of a likely **false positive**.

## 4. Hunt with IOCs
Recorded IOCs are matched against all imported events. A hit becomes a finding and feeds correlation.

## 5. Export
**Reports** builds the PDF (cover, executive summary, integrity table, timelines, evidence, notes, IOCs, remediation, methodology). Also export Markdown, JSON, evidence CSV and IOC CSV. Rebuild the PDF after changing verdicts or notes.

## Saving work
IOCs, notes, states and checklists are saved automatically in `traceforge_data/traceforge.db`. Their incident identity is stable, so they stay attached even if you change thresholds and incidents are renumbered. Use **Reports -> Case file** to move them to another machine.

## Command line
```bash
python -m traceforge.cli analyze sample_data/* --case "Demo" --analyst "You" \
  --ioc 198.51.100.77 --config config/example_thresholds.json --pdf report.pdf
```


## Security features in the console (v1.1)

- **Opening the console.** It opens directly on your computer. If you started it with `--require-token` (or on a network address, or in Docker) use the link printed in the terminal; without it the page shows "Access token required".
- **Evidence survives restarts.** Imported files are kept as read-only copies beside the database and checked again every time TraceForge starts. If a file no longer matches its SHA-256 a red bar appears and the file is excluded; upload the original again to repair it.
- **Audit page.** Shows integrity status, the audit hash chain, and every recorded action. Download it as CSV. Record the head hash elsewhere if you need to prove nothing was removed.
- **Archives.** `.zip` and `.gz` uploads are expanded safely; Windows Event XML, Zeek logs and CloudTrail JSON are recognised automatically.
- **Sharing.** Under **Reports -> Sharing & standards** choose how identifiers are masked. By default the marking decides: TLP:GREEN masks usernames, hostnames and internal IPs; TLP:CLEAR also withholds notes and the organisation name. STIX 2.1 indicators and an ATT&CK Navigator layer can be exported there too.
- **Encrypted case file.** Save and restore your case with a passphrase (minimum 10 characters). A lost passphrase cannot be recovered.
- **Sigma rules.** Settings -> Imported Sigma rules. Rules using aggregation (`count`, `near`) are skipped with a reason.
